#!/usr/bin/env python3
"""
中国银行香港余额重放脚本
基于 simple_balance_request.py 和 mitmproxy2swagger_enhanced.py
专门用于重放中行账户余额查询请求
"""

import json
import requests
import urllib3
import re
import time
import os
import base64
from mitmproxy import io, http
from urllib.parse import urlparse
import collections

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def auto_detect_bank_apis(mitm_file_path):
    """自动检测抓包文件中的银行API"""
    bank_apis = {}
    
    try:
        with open(mitm_file_path, "rb") as logfile:
            freader = io.FlowReader(logfile)
            for flow in freader.stream():
                if isinstance(flow, http.HTTPFlow):
                    url = flow.request.pretty_url.lower()
                    parsed = urlparse(url)
                    domain = parsed.netloc.lower()
                    
                    # 识别中国银行香港
                    if 'bochk.com' in domain and 'acc.overview.do' in url:
                        bank_apis['boc_hk'] = {
                            'name': '中国银行香港',
                            'domain': 'its.bochk.com',
                            'api_endpoint': 'acc.overview.do',
                            'flow': flow,
                            'url': flow.request.pretty_url
                        }
                    
                    # 识别招商永隆银行
                    elif 'cmbwinglungbank.com' in domain and 'McpCSReqServlet' in url:
                        bank_apis['cmb_wing_lung'] = {
                            'name': '招商永隆银行',
                            'domain': 'www.cmbwinglungbank.com',
                            'api_endpoint': 'McpCSReqServlet',
                            'flow': flow,
                            'url': flow.request.pretty_url
                        }
        
        return bank_apis
    except Exception as e:
        print(f"❌ 检测银行API失败: {e}")
        return {}


def save_mitm_analysis_to_file(flow, bank_name):
    """保存mitmproxy解密分析到文件"""
    timestamp = int(time.time())
    filename = f"/Users/gu/IdeaProjects/reclaim/mitmproxy2swagger/repeat_request_bank/boc_mitm_analysis_{timestamp}.json"
    
    # 分析flow对象的详细信息
    mitm_analysis = {
        "bank_info": {
            "bank_name": bank_name,
            "target_api": "账户余额查询",
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        },
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
            "description": f"mitmproxy解密{bank_name}HTTPS流量分析",
            "process": [
                "1. mitmproxy作为中间人代理，拦截客户端与银行服务器的TLS连接",
                "2. 解密HTTPS请求，记录明文数据（包括session、cookie等认证信息）",
                "3. 解密银行服务器的HTML响应，提取账户余额数据",
                "4. 记录完整的请求-响应对，用于后续重放测试"
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
            "decrypted_content_preview": flow.response.text[:500] if flow.response else None,
            "contains_balance_data": flow.response and ('港元' in flow.response.text or 'HKD' in flow.response.text or '美元' in flow.response.text or 'USD' in flow.response.text) if flow.response else False
        }
    }
    
    # 保存到文件
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(mitm_analysis, f, indent=2, ensure_ascii=False)
        print(f"📁 {bank_name}HTTPS解密分析已保存到: {filename}")
        
        # 打印关键信息
        print(f"🔐 {bank_name}HTTPS解密分析:")
        print(f"   客户端TLS版本: {mitm_analysis['https_decryption_info']['tls_info']['client_tls_version']}")
        print(f"   服务端TLS版本: {mitm_analysis['https_decryption_info']['tls_info']['server_tls_version']}")
        print(f"   客户端加密套件: {mitm_analysis['https_decryption_info']['tls_info']['client_cipher']}")
        print(f"   服务端加密套件: {mitm_analysis['https_decryption_info']['tls_info']['server_cipher']}")
        print(f"   响应内容编码: {mitm_analysis['content_analysis']['response_content_encoding']}")
        print(f"   响应是否压缩: {mitm_analysis['content_analysis']['response_may_be_compressed']}")
        print(f"   解密后内容长度: {mitm_analysis['response_analysis']['content_length']} 字节")
        print(f"   包含余额数据: {mitm_analysis['content_analysis']['contains_balance_data']}")
        
        return filename
    except Exception as e:
        print(f"❌ 保存HTTPS分析失败: {e}")
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
                    if 'session' in key.lower() or 'jsessionid' in key.lower():
                        session_id = val
    
    # 对于中行，GET请求通常没有请求体
    body_params = {}
    if request.content:
        try:
            body_str = request.content.decode('utf-8')
            # 如果有请求体参数，解析它们
            from urllib.parse import parse_qs
            parsed = parse_qs(body_str)
            for key, values in parsed.items():
                body_params[key] = values[0] if values else ''
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


def extract_boc_balance(response_text):
    """从中国银行香港响应中提取余额数据"""
    balances = {}
    
    # 中行HTML响应的余额提取模式
    patterns = {
        'HKD': [
            r'港元\s*\(HKD\)</td>[^<]*<td[^>]*>([^<]*\d[^<]*)</td>',
            r'>港元 \(HKD\)</td>[^<]*<td[^>]*>([^<]*\d[^<]*)</td>',
            r'data_table_swap1_txt[^>]*>(\d[\d,]*\.\d{2})</td>',
            r'HKD[^\d]*(\d[\d,]*\.\d{2})',
        ],
        'USD': [
            r'美元\s*\(USD\)</td>[^<]*<td[^>]*>([^<]*\d[^<]*)</td>',
            r'>美元 \(USD\)</td>[^<]*<td[^>]*>([^<]*\d[^<]*)</td>',
            r'data_table_swap2_txt[^>]*>(\d[\d,]*\.\d{2})</td>',
            r'USD[^\d]*(\d[\d,]*\.\d{2})',
        ],
        'TOTAL_HKD': [
            r'data_table_subtotal[^>]*>(\d[\d,]*\.\d{2})</td>',
            r'小計.*?(\d[\d,]*\.\d{2})',
            r'總計.*?(\d[\d,]*\.\d{2})',
        ]
    }
    
    for currency, currency_patterns in patterns.items():
        for pattern in currency_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if matches:
                # 清理匹配结果
                cleaned_matches = []
                for match in matches:
                    # 提取数字部分
                    amount_match = re.search(r'(\d[\d,]*\.\d{2})', match)
                    if amount_match:
                        cleaned_matches.append(amount_match.group(1))
                
                if cleaned_matches:
                    balances[currency] = cleaned_matches
                    break  # 找到匹配后跳出内层循环
    
    return balances


def save_boc_request_details_to_file(req_data, response, balances, bank_name):
    """保存中国银行香港请求详细信息到文件"""
    timestamp = int(time.time())
    filename = f"/Users/gu/IdeaProjects/reclaim/mitmproxy2swagger/repeat_request_bank/boc_request_details_{timestamp}.json"
    
    # 分析响应内容中的余额位置
    balance_analysis = {}
    if response and balances:
        response_text = response.text
        for currency, amounts in balances.items():
            for amount in amounts:
                balance_pos = response_text.find(amount)
                if balance_pos >= 0:
                    # 提取余额周围的内容 (前后各200字符)
                    start_pos = max(0, balance_pos - 200)
                    end_pos = min(len(response_text), balance_pos + 200)
                    balance_context = response_text[start_pos:end_pos]
                    
                    balance_analysis[f"{currency}_{amount}"] = {
                        "currency": currency,
                        "amount": amount,
                        "position": balance_pos,
                        "context": balance_context,
                        "context_start": start_pos,
                        "context_end": end_pos
                    }
    
    # 构建完整的请求信息
    request_details = {
        "bank_info": {
            "bank_name": bank_name,
            "bank_code": "boc_hk",
            "api_type": "账户余额查询",
            "api_endpoint": "acc.overview.do"
        },
        "timestamp": timestamp,
        "time_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "success": True,
        "balances_found": balances,
        "total_balances_count": sum(len(amounts) for amounts in balances.values()) if balances else 0,
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
            "content_preview": response.text[:1000] if response else None,
            "content_full": response.text if response else None,  # 完整响应内容
            "contains_balance": bool(balances),
            "response_format": "HTML"
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
                        "value": "港元\\s*\\(HKD\\)</td>[^<]*<td[^>]*>([^<]*\\d[^<]*)</td>",
                        "description": "匹配HKD余额"
                    },
                    {
                        "type": "regex", 
                        "value": "美元\\s*\\(USD\\)</td>[^<]*<td[^>]*>([^<]*\\d[^<]*)</td>",
                        "description": "匹配USD余额"
                    }
                ],
                "responseRedactions": [
                    {
                        "regex": "港元\\s*\\(HKD\\)</td>[^<]*<td[^>]*>([^<]*\\d[^<]*)</td>",
                        "description": "提取HKD余额数据"
                    },
                    {
                        "regex": "美元\\s*\\(USD\\)</td>[^<]*<td[^>]*>([^<]*\\d[^<]*)</td>",
                        "description": "提取USD余额数据"
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
        print(f"📁 {bank_name}完整请求详情已保存到: {filename}")
        
        # 额外打印余额分析信息
        if balance_analysis:
            print(f"💰 {bank_name}余额信息分析:")
            for balance_key, balance_info in balance_analysis.items():
                print(f"   {balance_info['currency']}: {balance_info['amount']}")
                print(f"   位置: {balance_info['position']}")
            print(f"   响应总长度: {len(response.text) if response else 0}")
        
        return filename
    except Exception as e:
        print(f"❌ 保存文件失败: {e}")
        return None


def replay_boc_balance_request():
    """重放中国银行香港余额请求"""
    mitm_file = "/Users/gu/IdeaProjects/reclaim/mitmproxy2swagger/testdata/flows_with_balance.mitm"
    
    print("🏦 中国银行香港 - 账户余额重放请求")
    print("-" * 50)
    
    # 1. 自动检测银行API
    print("🔍 自动检测银行API...")
    bank_apis = auto_detect_bank_apis(mitm_file)
    
    if 'boc_hk' not in bank_apis:
        print("❌ 未找到中国银行香港的余额请求")
        print("📋 检测到的银行API:")
        for bank_code, bank_info in bank_apis.items():
            print(f"   {bank_info['name']}: {bank_info['domain']}")
        return None
    
    bank_info = bank_apis['boc_hk']
    flow = bank_info['flow']
    
    print(f"✅ 找到中国银行香港API: {bank_info['url'][:80]}...")
    
    # 2. 保存HTTPS解密分析
    save_mitm_analysis_to_file(flow, bank_info['name'])
    
    # 3. 提取请求参数
    req_data = flow_to_request_data(flow)
    
    # 输出详细的API调用信息
    print("\n" + "="*80)
    print("📋 中国银行香港API详细信息 (用于Attestor调用)")
    print("="*80)
    print(f"🌐 完整URL: {req_data['url']}")
    print(f"📤 请求方法: {req_data['method']}")
    print(f"🔑 会话ID: {req_data['session_id'][:20]}..." if req_data['session_id'] else "N/A")
    
    print(f"\n🍪 Cookie信息:")
    for key, value in req_data['cookies'].items():
        display_val = value[:30] + "..." if len(value) > 30 else value
        print(f"   {key}: {display_val}")
    
    print(f"\n📤 关键请求头:")
    important_headers = ['User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding', 'Cache-Control', 'Referer']
    for key, value in req_data['headers'].items():
        if key in important_headers:
            print(f"   {key}: {value}")
    
    print("\n" + "="*80)
    
    # 4. 发送HTTPS请求
    print("🚀 发送重放请求...")
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
        
        # 5. 提取中行余额
        balances = extract_boc_balance(response.text)
        
        # 6. 保存完整请求详情到文件
        saved_file = save_boc_request_details_to_file(req_data, response, balances, bank_info['name'])
        
        if balances:
            print(f"💰 中国银行香港账户余额:")
            for currency, amounts in balances.items():
                for amount in amounts:
                    currency_name = {
                        'HKD': '港元',
                        'USD': '美元', 
                        'TOTAL_HKD': '港元总计'
                    }.get(currency, currency)
                    print(f"   {currency_name}: {amount}")
            
            # 输出Attestor调用所需的关键信息
            print("\n" + "="*80)
            print("🤖 Attestor调用信息总结")
            print("="*80)
            print("✅ 成功验证: 中国银行香港API可以正常获取余额数据")
            for currency, amounts in balances.items():
                currency_name = {
                    'HKD': '港元',
                    'USD': '美元',
                    'TOTAL_HKD': '港元总计'
                }.get(currency, currency)
                print(f"✅ {currency_name}余额: {', '.join(amounts)}")
            print(f"✅ 会话ID: {req_data['session_id'][:15]}...{req_data['session_id'][-15:] if req_data['session_id'] else 'N/A'}")
            print("✅ API端点: its.bochk.com/acc.overview.do")
            print("✅ 操作类型: acc.overview.do (账户概览)")
            print("✅ 响应格式: HTML (包含表格数据)")
            print(f"✅ 详细请求信息已保存到: {os.path.basename(saved_file) if saved_file else 'N/A'}")
            print("="*80)
            
            return {
                'bank': bank_info['name'],
                'bank_code': 'boc_hk',
                'balances': balances,
                'session_id': req_data['session_id'],
                'api_data': req_data,
                'saved_file': saved_file,
                'total_amounts': sum(len(amounts) for amounts in balances.values())
            }
        else:
            print("⚠️  未找到余额数据")
            # 保存失败的请求详情
            save_boc_request_details_to_file(req_data, response, {}, bank_info['name'])
            # 打印响应的前1000字符用于调试
            print("📝 响应内容预览:")
            print(response.text[:1000])
            print("..." if len(response.text) > 1000 else "")
            return None
            
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        # 保存失败的请求详情
        save_boc_request_details_to_file(req_data, None, {}, bank_info['name'])
        return None


if __name__ == "__main__":
    result = replay_boc_balance_request()
    
    if result and isinstance(result, dict):
        print(f"\n✅ 成功获取{result['bank']}余额:")
        for currency, amounts in result['balances'].items():
            currency_name = {
                'HKD': '港元',
                'USD': '美元',
                'TOTAL_HKD': '港元总计'
            }.get(currency, currency)
            print(f"   {currency_name}: {', '.join(amounts)}")
        
        print(f"\n🔗 接下来可以使用以下信息调用Attestor:")
        print(f"   银行: {result['bank']} ({result['bank_code']})")
        print(f"   Session ID: {result['session_id']}")
        print(f"   余额总数: {result['total_amounts']} 个数据点")
        if result.get('saved_file'):
            print(f"   详细配置文件: {result['saved_file']}")
    else:
        print(f"\n❌ 无法获取余额 (可能session已过期或网络问题)")