#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
详细的网络流量分析器
分析mitmproxy抓包文件中的所有请求和响应内容
"""

import sys
import json
import gzip
from urllib.parse import parse_qs, unquote
from mitmproxy import io, http

def analyze_all_flows(mitm_file_path):
    """分析所有网络流量"""
    print(f"正在详细分析抓包文件: {mitm_file_path}")
    
    all_requests = []
    text_responses = []
    
    try:
        with open(mitm_file_path, "rb") as f:
            flow_reader = io.FlowReader(f)
            
            for i, flow in enumerate(flow_reader.stream()):
                if not isinstance(flow, http.HTTPFlow):
                    continue
                
                request = flow.request
                response = flow.response
                
                # 收集请求信息
                req_info = {
                    'flow_id': i + 1,
                    'method': request.method,
                    'url': request.pretty_url,
                    'host': request.host,
                    'path': request.path,
                    'headers': dict(request.headers),
                    'has_content': bool(request.content),
                    'content_length': len(request.content) if request.content else 0
                }
                
                # 解析请求内容
                if request.content:
                    req_info['request_content'] = analyze_content(
                        request.content, 
                        request.headers.get('content-type', '')
                    )
                
                # 解析响应内容
                if response and response.content:
                    resp_info = analyze_content(
                        response.content, 
                        response.headers.get('content-type', ''),
                        response.headers.get('content-encoding', '')
                    )
                    req_info['response'] = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': resp_info
                    }
                    
                    # 如果是文本响应，记录下来
                    if resp_info and 'text' in str(resp_info):
                        text_responses.append({
                            'flow_id': i + 1,
                            'url': request.pretty_url[:100],
                            'content': resp_info
                        })
                
                all_requests.append(req_info)
                
                # 打印重要请求
                if is_important_request(request):
                    print(f"\n=== 重要请求 #{i+1} ===")
                    print(f"URL: {request.pretty_url}")
                    print(f"Method: {request.method}")
                    print(f"Host: {request.host}")
                    
                    if request.content:
                        content_info = analyze_content(
                            request.content, 
                            request.headers.get('content-type', '')
                        )
                        if content_info:
                            print(f"请求内容: {json.dumps(content_info, ensure_ascii=False, indent=2)}")
                    
                    if response and response.content:
                        resp_content = analyze_content(
                            response.content, 
                            response.headers.get('content-type', ''),
                            response.headers.get('content-encoding', '')
                        )
                        if resp_content:
                            print(f"响应内容: {json.dumps(resp_content, ensure_ascii=False, indent=2)}")
                    
                    print("-" * 80)
    
    except Exception as e:
        print(f"读取抓包文件失败: {e}")
        return [], []
    
    return all_requests, text_responses

def analyze_content(content, content_type, content_encoding=''):
    """分析请求或响应内容"""
    if not content:
        return None
    
    # 处理压缩
    if content_encoding == 'gzip':
        try:
            content = gzip.decompress(content)
        except:
            pass
    
    content_type = content_type.lower()
    
    # JSON内容
    if 'json' in content_type:
        try:
            return json.loads(content.decode('utf-8'))
        except:
            pass
    
    # 表单数据
    elif 'form-urlencoded' in content_type:
        try:
            form_str = content.decode('utf-8')
            return dict(parse_qs(form_str))
        except:
            pass
    
    # 文本内容
    elif 'text' in content_type or 'xml' in content_type or 'html' in content_type:
        try:
            text = content.decode('utf-8')
            if len(text) < 5000:  # 只显示较短的文本
                return {'text': text}
            else:
                return {'text_preview': text[:2000] + '...(truncated)'}
        except:
            pass
    
    # 尝试解析为文本（即使content-type不是text）
    try:
        text = content.decode('utf-8')
        # 检查是否包含有意义的文本内容
        if any(keyword in text.lower() for keyword in ['message', 'content', 'text', 'msg', 'chat']):
            if len(text) < 5000:
                return {'potential_text': text}
            else:
                return {'potential_text_preview': text[:2000] + '...(truncated)'}
    except:
        pass
    
    # 二进制内容
    return {'binary_size': len(content), 'content_type': content_type}

def is_important_request(request):
    """判断是否是重要的请求"""
    url = request.pretty_url.lower()
    host = request.host.lower()
    
    # 重要关键词
    important_keywords = [
        'message', 'msg', 'chat', 'conversation', 'sync', 'send', 'receive',
        'api', 'post', 'data', 'json', 'cgi-bin', 'webwx', 'wechat', 'weixin',
        'login', 'auth', 'token', 'session'
    ]
    
    # 排除静态资源
    static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.ttf']
    if any(url.endswith(ext) for ext in static_extensions):
        return False
    
    # 检查是否包含重要关键词
    for keyword in important_keywords:
        if keyword in url or keyword in host:
            return True
    
    # POST请求通常比较重要
    if request.method == 'POST':
        return True
    
    return False

def main():
    if len(sys.argv) != 2:
        print("用法: python detailed_flow_analysis.py <mitm_file_path>")
        sys.exit(1)
    
    mitm_file = sys.argv[1]
    
    print("开始详细分析网络流量...")
    all_requests, text_responses = analyze_all_flows(mitm_file)
    
    print(f"\n{'='*60}")
    print(f"分析结果摘要:")
    print(f"{'='*60}")
    print(f"总请求数: {len(all_requests)}")
    print(f"包含文本响应的请求数: {len(text_responses)}")
    
    # 按域名分组统计
    domain_stats = {}
    method_stats = {}
    
    for req in all_requests:
        domain = req['host']
        method = req['method']
        
        domain_stats[domain] = domain_stats.get(domain, 0) + 1
        method_stats[method] = method_stats.get(method, 0) + 1
    
    print(f"\n域名统计:")
    for domain, count in sorted(domain_stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  {domain}: {count} 请求")
    
    print(f"\n请求方法统计:")
    for method, count in sorted(method_stats.items()):
        print(f"  {method}: {count} 请求")
    
    # 查找可能的聊天相关内容
    chat_related = []
    for req in all_requests:
        url_lower = req['url'].lower()
        if any(keyword in url_lower for keyword in ['message', 'msg', 'chat', 'sync', 'conversation']):
            chat_related.append(req)
    
    if chat_related:
        print(f"\n找到 {len(chat_related)} 个可能与聊天相关的请求:")
        for req in chat_related[:5]:  # 显示前5个
            print(f"  {req['method']} {req['url'][:100]}")
    
    # 保存详细结果
    result_file = mitm_file.replace('.mitm', '_detailed_analysis.json')
    result = {
        'summary': {
            'total_requests': len(all_requests),
            'text_responses': len(text_responses),
            'domain_stats': domain_stats,
            'method_stats': method_stats,
            'chat_related_count': len(chat_related)
        },
        'requests': all_requests[:100],  # 只保存前100个请求的详细信息
        'text_responses': text_responses[:50],  # 只保存前50个文本响应
        'chat_related': chat_related
    }
    
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    print(f"\n详细分析结果已保存到: {result_file}")

if __name__ == "__main__":
    main() 