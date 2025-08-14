#!/usr/bin/env python3
"""
银行余额请求重放脚本
从.mitm文件中提取银行余额API请求，并重新发送HTTPS请求获取实时余额数据
"""

import json
import sys
import argparse
import re
import requests
import urllib3
from typing import Dict, List, Optional, Any
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException

# 禁用SSL警告（因为可能需要处理自签名证书）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BankBalanceRequestReplay:
    """银行余额请求重放器"""
    
    def __init__(self, mitm_file_path: str):
        self.mitm_file_path = mitm_file_path
        self.session = requests.Session()
        
        # 银行API识别模式
        self.bank_patterns = {
            'cmb_wing_lung': {
                'url_pattern': 'cmbwinglungbank.com',
                'balance_endpoint': 'NbBkgActdetCoaProc2022',
                'currency_target': 'HKD'
            },
            'hsbc_hk': {
                'url_pattern': 'hsbc.com.hk',
                'balance_endpoint': [
                    'api/mmf-cust-accounts--hk-hbap-banking-prod-proxy',
                    '/v1/accounts/domestic',
                    '/v1/accounts'
                ],
                'currency_target': 'HKD'
            }
        }
    
    def load_mitm_flows(self) -> List[http.HTTPFlow]:
        """从.mitm文件加载HTTP流量"""
        flows = []
        try:
            print(f"🔄 正在读取抓包文件: {self.mitm_file_path}")
            
            with open(self.mitm_file_path, "rb") as logfile:
                freader = io.FlowReader(logfile)
                for flow in freader.stream():
                    if isinstance(flow, http.HTTPFlow):
                        flows.append(flow)
            
            print(f"✅ 成功加载 {len(flows)} 个HTTP流量记录")
            return flows
            
        except FileNotFoundError:
            print(f"❌ 错误: 找不到文件 {self.mitm_file_path}")
            return []
        except FlowReadException as e:
            print(f"❌ 错误: 无法读取抓包文件 - {e}")
            return []
        except Exception as e:
            print(f"❌ 错误: {e}")
            return []
    
    def is_balance_request(self, flow: http.HTTPFlow) -> bool:
        """判断是否为银行余额请求"""
        if not flow.request or not flow.request.pretty_url:
            return False
        
        url = flow.request.pretty_url.lower()
        
        # 检查是否匹配银行模式
        for bank_name, pattern in self.bank_patterns.items():
            if pattern['url_pattern'] in url:
                endpoints = pattern.get('balance_endpoint')
                if isinstance(endpoints, list):
                    if any(str(ep).lower() in url for ep in endpoints):
                        return True
                else:
                    if str(endpoints).lower() in url:
                        return True
        
        return False
    
    def extract_balance_requests(self, flows: List[http.HTTPFlow]) -> List[http.HTTPFlow]:
        """提取银行余额相关的请求"""
        balance_flows = []
        
        print("\n🔍 正在筛选银行余额相关请求...")
        
        for flow in flows:
            if self.is_balance_request(flow):
                balance_flows.append(flow)
                print(f"🎯 发现余额请求: {flow.request.method} {flow.request.pretty_url}")
        
        print(f"📊 总计找到 {len(balance_flows)} 个余额相关请求")
        return balance_flows

    def filter_requests_by(self,
                           flows: List[http.HTTPFlow],
                           host_contains: Optional[str] = None,
                           url_contains: Optional[str] = None,
                           exact_url: Optional[str] = None) -> List[http.HTTPFlow]:
        """按条件筛选请求（域名包含/URL包含/URL前缀精确匹配）"""
        results: List[http.HTTPFlow] = []
        for fl in flows:
            try:
                if not fl.request or not fl.request.pretty_url:
                    continue
                url = fl.request.pretty_url
                url_l = url.lower()
                if exact_url:
                    if url.startswith(exact_url):
                        results.append(fl)
                    continue
                if host_contains and host_contains.lower() not in url_l:
                    continue
                if url_contains and url_contains.lower() not in url_l:
                    continue
                if host_contains or url_contains:
                    results.append(fl)
            except Exception:
                continue
        return results

    def discover_balance_candidates(self,
                                    flows: List[http.HTTPFlow],
                                    host_contains: Optional[str] = None) -> List[dict]:
        """自动发现可能为余额查询的请求，返回带评分与提示的列表（高分在前）"""
        candidates: List[dict] = []
        for fl in flows:
            try:
                req = fl.request
                if not req or not req.pretty_url:
                    continue
                url = req.pretty_url
                if host_contains and host_contains.lower() not in url.lower():
                    continue

                score = 0
                hints: List[str] = []

                # 方法偏好
                if req.method.upper() == 'GET':
                    score += 1
                    hints.append('GET')

                # URL 关键词
                path_l = url.lower()
                url_hints = [
                    'balance', 'balances', 'account', 'accounts', 'arrangement', 'deposit', 'deposits',
                    '/v1/accounts', '/balances', '/domestic'
                ]
                hits = [h for h in url_hints if h in path_l]
                if hits:
                    score += len(hits)
                    hints.extend(hits)

                # 响应 JSON 内容线索
                resp = fl.response
                if resp and resp.headers and 'content-type' in resp.headers and \
                   str(resp.headers.get('content-type', '')).lower().startswith('application/json'):
                    hints.append('json')
                    score += 1
                    try:
                        text = resp.get_text(strict=False) or ''
                        if re.search(r'\b(balance|availableBalance|currentBalance|ledgerBalance)\b', text, re.I):
                            score += 3
                            hints.append('json_balance_keys')
                        if re.search(r'\bHKD\b', text):
                            score += 1
                            hints.append('HKD')
                    except Exception:
                        pass

                if score >= 3:
                    candidates.append({'flow': fl, 'score': score, 'hints': hints, 'url': url, 'method': req.method})
            except Exception:
                continue

        candidates.sort(key=lambda d: -d['score'])
        return candidates
    
    def flow_to_requests_kwargs(self, flow: http.HTTPFlow) -> Dict[str, Any]:
        """将mitmproxy flow转换为requests库可用的参数"""
        request = flow.request
        
        # 基础参数
        kwargs = {
            'method': request.method,
            'url': request.pretty_url,
            'verify': False,  # 忽略SSL证书验证
            'timeout': 30,
            'allow_redirects': True
        }
        
        # 提取headers
        headers = {}
        for name, value in request.headers.items():
            # 过滤掉一些可能导致问题的headers
            if name.lower() not in ['content-length', 'transfer-encoding']:
                headers[name] = value
        
        kwargs['headers'] = headers
        
        # 提取cookies
        if 'Cookie' in headers:
            # requests会自动处理Cookie header，但我们也可以单独设置
            cookie_str = headers['Cookie']
            cookies = {}
            for cookie_pair in cookie_str.split(';'):
                if '=' in cookie_pair:
                    key, value = cookie_pair.strip().split('=', 1)
                    cookies[key] = value
            kwargs['cookies'] = cookies
        
        # 处理请求体
        if request.content:
            if request.method.upper() in ['POST', 'PUT', 'PATCH']:
                kwargs['data'] = request.content
        
        return kwargs
    
    def print_request_details(self, kwargs: Dict[str, Any]):
        """打印请求详细信息"""
        print("\n" + "="*80)
        print("📤 发送请求详情")
        print("="*80)
        print(f"🔗 URL: {kwargs['url']}")
        print(f"📝 方法: {kwargs['method']}")
        
        print(f"\n📋 请求头:")
        for key, value in kwargs.get('headers', {}).items():
            # 隐藏敏感信息的部分内容
            if key.lower() in ['authorization', 'cookie']:
                display_value = value[:20] + "..." if len(value) > 20 else value
            else:
                display_value = value
            print(f"   {key}: {display_value}")
        
        if 'cookies' in kwargs:
            print(f"\n🍪 Cookies:")
            for key, value in kwargs['cookies'].items():
                display_value = value[:15] + "..." if len(value) > 15 else value
                print(f"   {key}: {display_value}")
        
        if 'data' in kwargs:
            print(f"\n📦 请求体长度: {len(kwargs['data'])} bytes")
            try:
                # 尝试解析为JSON并格式化显示
                data_str = kwargs['data'].decode('utf-8') if isinstance(kwargs['data'], bytes) else str(kwargs['data'])
                if data_str.strip().startswith('{'):
                    json_data = json.loads(data_str)
                    print(f"📦 请求体 (JSON):")
                    print(json.dumps(json_data, indent=2, ensure_ascii=False)[:500])
                else:
                    print(f"📦 请求体 (Raw): {data_str[:200]}...")
            except:
                print(f"📦 请求体 (Binary): {len(kwargs['data'])} bytes")
    
    def print_response_details(self, response: requests.Response):
        """打印响应详细信息"""
        print("\n" + "="*80)
        print("📥 收到响应详情")
        print("="*80)
        print(f"📊 状态码: {response.status_code}")
        print(f"⏱️  响应时间: {response.elapsed.total_seconds():.2f}秒")
        
        print(f"\n📋 响应头:")
        for key, value in response.headers.items():
            print(f"   {key}: {value}")
        
        print(f"\n📦 响应体长度: {len(response.content)} bytes")
        
        # 尝试解析响应内容
        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                json_data = response.json()
                print(f"📦 响应体 (JSON):")
                print(json.dumps(json_data, indent=2, ensure_ascii=False)[:1000])
            else:
                text_content = response.text
                print(f"📦 响应体 (Text):")
                print(text_content[:1000])
                if len(text_content) > 1000:
                    print(f"\n... (还有 {len(text_content) - 1000} 个字符)")
        except Exception as e:
            print(f"📦 响应体 (Raw bytes): {response.content[:200]}...")
            print(f"   解析错误: {e}")
    
    def extract_balance_from_response(self, response: requests.Response) -> Optional[Dict[str, Any]]:
        """从响应中提取余额数据"""
        try:
            content = response.text
            
            # 尝试提取HKD余额
            import re
            
            # 多种HKD余额提取模式
            hkd_patterns = [
                r'HKD[^\d]*(\d[\d,]*\.?\d*)',
                r'"(\d[\d,]*\.\d{2})"[^}]*HKD',
                r'港币.*?(\d[\d,]*\.\d{2})',
                r'HK\$.*?(\d[\d,]*\.\d{2})'
            ]
            
            extracted_balances = {}
            
            for pattern in hkd_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    extracted_balances['HKD'] = matches
                    break
            
            # 提取所有可能的金额数字
            all_amounts = re.findall(r'\d{1,3}(?:,\d{3})*\.\d{2}', content)
            if all_amounts:
                extracted_balances['all_detected_amounts'] = list(set(all_amounts))
            
            return extracted_balances if extracted_balances else None
            
        except Exception as e:
            print(f"❌ 提取余额数据时出错: {e}")
            return None
    
    def replay_balance_request(self, flow: http.HTTPFlow, override_headers: Optional[Dict[str, str]] = None, inject_cookie: Optional[str] = None) -> Optional[requests.Response]:
        """重放单个余额请求"""
        try:
            # 转换为requests参数
            kwargs = self.flow_to_requests_kwargs(flow)
            # 应用覆盖头与注入 Cookie
            if override_headers:
                headers = kwargs.get('headers', {})
                headers.update(override_headers)
                kwargs['headers'] = headers
            if inject_cookie:
                headers = kwargs.get('headers', {})
                headers['Cookie'] = inject_cookie
                kwargs['headers'] = headers
            
            # 打印请求详情
            self.print_request_details(kwargs)
            
            print(f"\n🚀 正在发送请求到: {kwargs['url']}")
            
            # 发送请求
            response = self.session.request(**kwargs)
            
            # 打印响应详情
            self.print_response_details(response)
            
            # 尝试提取余额数据
            balance_data = self.extract_balance_from_response(response)
            if balance_data:
                print(f"\n💰 提取到的余额数据:")
                for currency, amounts in balance_data.items():
                    print(f"   {currency}: {amounts}")
            else:
                print(f"\n⚠️  未能从响应中提取到余额数据")
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"❌ 请求失败: {e}")
            return None
        except Exception as e:
            print(f"❌ 重放请求时出错: {e}")
            return None
    
    def run(self):
        """运行重放程序"""
        print("🎯 银行余额请求重放器启动")
        print("-" * 50)
        
        # 加载流量文件
        flows = self.load_mitm_flows()
        if not flows:
            print("❌ 无法加载流量数据，程序退出")
            return
        
        # 提取余额请求
        balance_flows = self.extract_balance_requests(flows)
        if not balance_flows:
            print("❌ 未找到银行余额相关请求，程序退出")
            return
        
        # 重放每个余额请求
        successful_replays = 0
        for i, flow in enumerate(balance_flows, 1):
            print(f"\n{'='*80}")
            print(f"🔄 重放请求 {i}/{len(balance_flows)}")
            print(f"{'='*80}")
            
            response = self.replay_balance_request(flow)
            if response and response.status_code == 200:
                successful_replays += 1
        
        # 总结
        print(f"\n{'='*80}")
        print(f"📊 重放完成总结")
        print(f"{'='*80}")
        print(f"✅ 成功重放: {successful_replays}/{len(balance_flows)} 个请求")
        
        if successful_replays == 0:
            print("⚠️  所有请求都失败了，可能的原因:")
            print("   1. Session已过期")
            print("   2. 银行有防重放机制")
            print("   3. 网络连接问题")
            print("   4. 请求参数已变更")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="银行余额请求重放器")
    parser.add_argument("--mitm", dest="mitm", default="/Users/gu/IdeaProjects/reclaim/mitmproxy2swagger/testdata/flows_with_balance.mitm", help="mitm 流量文件路径")
    parser.add_argument("--host", dest="host_contains", default=None, help="仅匹配包含该域名片段的请求，如 hsbc.com.hk")
    parser.add_argument("--contains", dest="url_contains", default=None, help="仅匹配 URL 中包含该子串的请求")
    parser.add_argument("--exact-url", dest="exact_url", default=None, help="仅匹配以该 URL 前缀开头的请求")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", help="只打印请求，不实际发送")
    parser.add_argument("--auto-balance", dest="auto_balance", action="store_true", help="自动发现疑似余额接口并（可选）重放")
    parser.add_argument("--top-k", dest="top_k", type=int, default=5, help="自动发现时展示/处理的前K条")
    parser.add_argument("--output", dest="output", default=None, help="将匹配请求摘要输出为 JSON 文件路径")
    parser.add_argument("--inject-cookie", dest="inject_cookie", default=None, help="覆盖请求的 Cookie 值（整串，如 k1=v1; k2=v2）")
    parser.add_argument("--set-header", dest="set_headers", action="append", default=None, help="覆盖/追加请求头（可多次），格式: 'Header-Name: value'")

    args = parser.parse_args()

    mitm_file_path = args.mitm
    print("🏦 银行活期账户余额获取工具")
    print("="*50)
    print(f"📁 目标文件: {mitm_file_path}")
    print("🎯 目标: 获取活期HKD账户余额")
    if any([args.host_contains, args.url_contains, args.exact_url]):
        print("🔍 使用自定义筛选条件进行匹配")
    print("⚠️  注意: 此工具将重放真实的银行API请求\n")

    replayer = BankBalanceRequestReplay(mitm_file_path)

    # 解析 --set-header 列表为字典
    override_headers: Dict[str, str] = {}
    if args.set_headers:
        for entry in args.set_headers:
            if not isinstance(entry, str) or ':' not in entry:
                continue
            name, value = entry.split(':', 1)
            override_headers[name.strip()] = value.strip()

    flows = replayer.load_mitm_flows()
    if not flows:
        print("❌ 无法加载流量数据，程序退出")
        return

    if args.auto_balance:
        candidates = replayer.discover_balance_candidates(flows, host_contains=args.host_contains)
        top = candidates[: max(1, args.top_k)]
        print(f"📊 发现疑似余额接口 {len(candidates)} 条，展示前 {len(top)} 条：")
        for i, c in enumerate(top, 1):
            print(f"{i:02d}. [{c['score']}] {c['method']} {c['url']}\n    hints: {c['hints']}")
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump([
                        { 'url': c['url'], 'method': c['method'], 'score': c['score'], 'hints': c['hints'] }
                        for c in top
                    ], f, ensure_ascii=False, indent=2)
                print(f"💾 已写出: {args.output}")
            except Exception as e:
                print(f"❌ 写出失败: {e}")

        matched_flows = [c['flow'] for c in top]
        if args.dry_run:
            print("📝 dry-run 模式：不重放请求")
            return
        successful = 0
        for i, flow in enumerate(matched_flows, 1):
            print(f"\n{'='*80}")
            print(f"🔄 重放自动发现请求 {i}/{len(matched_flows)}")
            print(f"{'='*80}")
            resp = replayer.replay_balance_request(flow, override_headers=override_headers or None, inject_cookie=args.inject_cookie)
            if resp and resp.status_code == 200:
                successful += 1
        print(f"\n✅ 自动发现请求重放完成，成功: {successful}/{len(matched_flows)}")
        return

    if any([args.host_contains, args.url_contains, args.exact_url]):
        matched = replayer.filter_requests_by(
            flows,
            host_contains=args.host_contains,
            url_contains=args.url_contains,
            exact_url=args.exact_url,
        )
        print(f"📊 自定义条件匹配到 {len(matched)} 条请求")
    else:
        matched = replayer.extract_balance_requests(flows)
        if not matched:
            print("❌ 未找到银行余额相关请求，程序退出")
            return

    successful = 0
    for i, flow in enumerate(matched, 1):
        print(f"\n{'='*80}")
        print(f"🔄 处理请求 {i}/{len(matched)}")
        print(f"{'='*80}")
        kwargs = replayer.flow_to_requests_kwargs(flow)
        # 在打印前应用覆盖，保持展示与实际发送一致
        if override_headers:
            headers = kwargs.get('headers', {})
            headers.update(override_headers)
            kwargs['headers'] = headers
        if args.inject_cookie:
            headers = kwargs.get('headers', {})
            headers['Cookie'] = args.inject_cookie
            kwargs['headers'] = headers
        replayer.print_request_details(kwargs)
        if args.dry_run:
            continue
        resp = replayer.replay_balance_request(flow, override_headers=override_headers or None, inject_cookie=args.inject_cookie)
        if resp and resp.status_code == 200:
            successful += 1

    print(f"\n{'='*80}")
    print("📊 处理完成总结")
    print(f"{'='*80}")
    if args.dry_run:
        print(f"📝 仅打印：共 {len(matched)} 条请求")
    else:
        print(f"✅ 成功重放: {successful}/{len(matched)} 条请求")


if __name__ == "__main__":
    main() 