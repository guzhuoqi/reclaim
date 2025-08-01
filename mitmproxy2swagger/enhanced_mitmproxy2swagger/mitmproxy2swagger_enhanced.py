#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Enhanced mitmproxy2swagger with Balance Data Extraction
集成了余额数据提取功能的增强版mitmproxy2swagger
"""

import argparse
import json
import os
import re
import sys
import traceback
import urllib
from typing import Any, Optional, Sequence, Union

import msgpack
import ruamel.yaml
from mitmproxy.exceptions import FlowReadException

# 导入原始mitmproxy2swagger模块
from mitmproxy2swagger import console_util, swagger_util
from mitmproxy2swagger.har_capture_reader import HarCaptureReader, har_archive_heuristic
from mitmproxy2swagger.mitmproxy_capture_reader import (
    MitmproxyCaptureReader,
    mitmproxy_dump_file_huristic,
)

# 导入我们的余额数据提取器（现在在同一目录下）
from balance_data_extractor import enhance_response_processing, get_balance_examples_for_endpoint


def enhanced_main(override_args: Optional[Sequence[str]] = None):
    """增强版main函数，支持余额数据提取"""
    
    parser = argparse.ArgumentParser(
        description="Enhanced mitmproxy2swagger with balance data extraction capability."
    )
    parser.add_argument(
        "-i",
        "--input",
        help="The input mitmproxy dump file or HAR dump file (from DevTools)",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="The output swagger schema file (yaml). If it exists, new endpoints will be added",
        required=True,
    )
    parser.add_argument("-p", "--api-prefix", help="The api prefix (optional, will auto-detect if not provided)", required=False)
    parser.add_argument(
        "-e",
        "--examples",
        action="store_true",
        help="Include examples in the schema. This might expose sensitive information.",
    )
    parser.add_argument(
        "-hd",
        "--headers",
        action="store_true",
        help="Include headers in the schema. This might expose sensitive information.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["flow", "har"],
        help="Override the input file format auto-detection.",
    )
    parser.add_argument(
        "-r",
        "--param-regex",
        default="[0-9]+",
        help="Regex to match parameters in the API paths. Path segments that match this regex will be turned into parameter placeholders.",
    )
    parser.add_argument(
        "-s",
        "--suppress-params",
        action="store_true",
        help="Do not include API paths that have the original parameter values, only the ones with placeholders.",
    )
    # 新增：余额数据提取选项
    parser.add_argument(
        "--extract-balance",
        action="store_true",
        help="Enable balance data extraction for banking APIs. This will extract and include actual balance amounts in the schema.",
    )
    parser.add_argument(
        "--balance-plaintext",
        action="store_true", 
        help="Include plaintext balance data in examples (use only with user consent for personal data).",
    )
    
    args = parser.parse_args(override_args)

    try:
        args.param_regex = re.compile("^" + args.param_regex + "$")
    except re.error as e:
        print(
            f"{console_util.ANSI_RED}Invalid path parameter regex: {e}{console_util.ANSI_RESET}"
        )
        sys.exit(1)

    yaml = ruamel.yaml.YAML()

    # 检测输入格式
    capture_reader: Union[MitmproxyCaptureReader, HarCaptureReader]
    if args.format == "flow" or args.format == "mitmproxy":
        capture_reader = MitmproxyCaptureReader(args.input, progress_callback)
    elif args.format == "har":
        capture_reader = HarCaptureReader(args.input, progress_callback)
    else:
        capture_reader = detect_input_format(args.input)

    # 🎯 自动检测API前缀（如果未提供）
    if not args.api_prefix:
        api_prefixes = auto_detect_api_prefixes(capture_reader)
        args.api_prefix = api_prefixes[0]  # 主要前缀用于兼容性
        args.all_api_prefixes = api_prefixes  # 所有前缀用于多银行处理
        print(f"🔍 自动检测到 {len(api_prefixes)} 个API前缀:")
        for prefix in api_prefixes:
            print(f"   - {prefix}")
    else:
        args.all_api_prefixes = [args.api_prefix]
    
    # 加载或创建swagger规范  
    swagger = load_or_create_swagger_spec(args, yaml)
    
    # 处理路径模板
    path_templates, path_template_regexes = setup_path_templates(swagger)
    new_path_templates = []

    try:
        balance_data_cache = {}  # 缓存提取的余额数据
        
        for req in capture_reader.captured_requests():
            # 基础URL和路径处理 - 支持多个API前缀
            url = None
            path = None
            current_api_prefix = None
            
            # 尝试匹配任何一个API前缀
            for api_prefix in args.all_api_prefixes:
                matched_url = req.get_matching_url(api_prefix)
                if matched_url is not None:
                    url = matched_url
                    path = strip_query_string(url).removeprefix(api_prefix)
                    current_api_prefix = api_prefix
                    break
            
            # 如果没有匹配任何前缀，跳过
            if url is None:
                continue
                
            method = req.get_method().lower()
            status = req.get_response_status_code()

            # 路径模板匹配
            path_template_index = find_path_template_match(path, path_template_regexes)
            if path_template_index is None:
                if path in new_path_templates:
                    # 🎯 修改：即使是重复的新路径，也要检查是否包含余额数据
                    path_template_to_set = path
                else:
                    new_path_templates.append(path)
                    path_template_to_set = path
            else:
                path_template_to_set = path_templates[path_template_index]
            
            # 确保路径存在于swagger中
            ensure_swagger_path_exists(swagger, path_template_to_set, method)

            # 处理请求参数和headers
            process_request_data(swagger, path_template_to_set, method, req, url, args)

            # 🎯 增强的响应处理逻辑
            response_body = req.get_response_body()
            if response_body is not None:
                # 原始响应处理
                original_response, original_content_type = parse_standard_response(response_body)
                
                # 🚀 新增：余额数据增强处理
                if args.extract_balance:
                    print(f"🔍 检查URL是否包含余额数据: {url}")
                    
                    # 尝试从原始响应体中提取余额数据，即使标准解析失败
                    enhanced_response, schema_enhancement = enhance_response_processing(
                        url, response_body, original_response
                    )
                    
                    if schema_enhancement:
                        # 使用增强的响应数据
                        response_to_use = enhanced_response
                        content_type_to_use = original_content_type or "text/plain"
                        
                        # 缓存余额数据用于后续处理
                        balance_data_cache[url] = enhanced_response.get('extracted_balance_data', {})
                        
                        print(f"🎯 检测到余额数据: {url}")
                        print(f"💰 提取余额: {balance_data_cache[url].get('raw_amounts', [])}")
                        
                    else:
                        print(f"❌ 未检测到余额数据: {url}")
                        # 使用原始响应
                        response_to_use = original_response
                        content_type_to_use = original_content_type
                else:
                    # 使用原始响应
                    response_to_use = original_response
                    content_type_to_use = original_content_type

                # 设置响应数据到swagger
                if response_to_use is not None:
                    resp_data_to_set = create_response_spec(
                        response_to_use, content_type_to_use, req, args, url
                    )
                    
                    # 🎯 增强schema信息
                    if args.extract_balance and url in balance_data_cache:
                        balance_data = balance_data_cache[url]
                        if balance_data and 'balances' in balance_data:
                            # 添加余额相关的schema描述
                            resp_data_to_set['description'] += f" (Contains balance data: {', '.join(balance_data['balances'].keys())})"
                            
                            # 如果启用了明文展示，生成实际的余额示例数据
                            if args.balance_plaintext:
                                # ⚠️ 重要：传递实际提取的余额数据，不使用任何硬编码数据
                                balance_examples = get_balance_examples_for_endpoint(url, balance_data)
                                if balance_examples:
                                    resp_data_to_set['content'][content_type_to_use]['x-balance-examples'] = balance_examples
                                    
                                    # 同时生成标准的OpenAPI example字段
                                    resp_data_to_set['content'][content_type_to_use]['example'] = {
                                        'original_response': {},
                                        'extracted_balance_data': balance_data
                                    }

                    swagger["paths"][path_template_to_set][method]["responses"][str(status)] = resp_data_to_set

            # 确保至少有一个响应
            ensure_default_response(swagger, path_template_to_set, method, req)

    except FlowReadException as e:
        handle_flow_read_error(e, args, capture_reader)

    # 保存增强的swagger文件
    save_enhanced_swagger(swagger, new_path_templates, args, yaml, balance_data_cache)

    # 打印增强处理总结
    if args.extract_balance and balance_data_cache:
        print_balance_extraction_summary(balance_data_cache)


def parse_standard_response(response_body):
    """解析标准响应格式"""
    try:
        response_parsed = json.loads(response_body)
        return response_parsed, "application/json"
    except (UnicodeDecodeError, json.decoder.JSONDecodeError):
        pass

    try:
        response_parsed = msgpack.loads(response_body)
        return response_parsed, "application/msgpack"
    except Exception:
        pass

    return None, None


def create_response_spec(response_data, content_type, req, args, url):
    """创建响应规范"""
    resp_data_to_set = {
        "description": req.get_response_reason(),
        "content": {
            content_type: {
                "schema": swagger_util.value_to_schema(response_data)
            }
        },
    }
    
    if args.examples:
        resp_data_to_set["content"][content_type]["example"] = swagger_util.limit_example_size(response_data)
    
    if args.headers:
        resp_data_to_set["headers"] = swagger_util.response_to_headers(req.get_response_headers())
    
    return resp_data_to_set


def is_static_resource(path):
    """检查路径是否是静态资源文件"""
    static_extensions = [
        '.css', '.js', '.gif', '.jpg', '.jpeg', '.png', '.ico', '.svg', 
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.html', '.htm', '.pdf'
    ]
    
    static_paths = [
        '/images/', '/css/', '/js/', '/fonts/', '/assets/', '/static/',
        '/banner/', '/CQ/', '/login/images/'
    ]
    
    path_lower = path.lower()
    
    # 检查文件扩展名
    if any(path_lower.endswith(ext) for ext in static_extensions):
        return True
        
    # 检查路径前缀
    if any(static_path in path_lower for static_path in static_paths):
        return True
        
    return False

def is_potential_balance_api(path):
    """检查路径是否可能是余额相关的API - 更严格的过滤"""
    # 首先排除静态资源
    if is_static_resource(path):
        return False
    
    # 只保留最核心的余额相关关键词
    balance_keywords = [
        'acc.overview.do',  # 中国银行账户概览
        'McpCSReqServlet',  # 招商永隆银行API
        'NbBkgActdetCoaProc', # 招商永隆银行余额查询
        'account', 'balance', 'overview', 'summary'
    ]
    
    path_lower = path.lower()
    return any(keyword in path_lower for keyword in balance_keywords)

def save_enhanced_swagger(swagger, new_path_templates, args, yaml, balance_data_cache):
    """保存增强的swagger文件"""
    
    # 添加新发现的路径模板
    if new_path_templates:
        # 🎯 修改：检查路径是否包含余额数据或是潜在的余额API
        processed_templates = []
        for path in new_path_templates:
            # 检查是否有URL包含此路径且在余额数据缓存中
            has_balance_data = any(path in url for url in balance_data_cache.keys())
            # 🚀 新增：即使没有检测到余额数据，也识别潜在的余额API
            is_balance_api = is_potential_balance_api(path)
            
            if has_balance_data or is_balance_api:
                # 包含余额数据或潜在余额API的路径不加ignore前缀
                processed_templates.append(path)
                if has_balance_data:
                    print(f"✅ 已检测余额数据的API路径: {path}")
                else:
                    print(f"🔍 潜在余额API路径（基于关键词识别）: {path}")
            else:
                # 不相关的路径加ignore前缀（主要是静态资源）
                processed_templates.append(f"ignore:{path}")
        
        swagger["x-path-templates"].extend(processed_templates)

    # 🎯 清理paths：只保留包含余额数据的API端点和关键认证API
    if 'paths' in swagger:
        filtered_paths = {}
        for path, path_data in swagger['paths'].items():
            # 检查这个路径是否对应包含余额数据的URL
            path_has_balance = False
            for url in balance_data_cache.keys():
                if path in url:
                    path_has_balance = True
                    break
            
            # 或者检查是否有响应描述包含余额数据信息
            if not path_has_balance:
                for method, method_data in path_data.items():
                    if isinstance(method_data, dict) and 'responses' in method_data:
                        for response_data in method_data['responses'].values():
                            if isinstance(response_data, dict) and 'Contains balance data' in response_data.get('description', ''):
                                path_has_balance = True
                                break
                    if path_has_balance:
                        break
            
            # 保留包含余额数据的API或重要的认证API，但排除图片等静态资源
            if path_has_balance:
                # 有余额数据的API一定保留
                filtered_paths[path] = path_data
            elif any(keyword in path.lower() for keyword in ['logon', 'login']) and not is_static_resource(path):
                # 认证API保留，但排除静态资源
                filtered_paths[path] = path_data
                
        swagger['paths'] = filtered_paths
        print(f"🎯 优化后保留了 {len(filtered_paths)} 个关键API端点（原{len(swagger.get('paths', {}))}个）")

    # 🎯 添加余额数据元信息
    if balance_data_cache:
        swagger["x-balance-extraction-info"] = {
            "extracted_endpoints": len(balance_data_cache),
            "supported_banks": list(set(
                data.get('bank', 'unknown') for data in balance_data_cache.values()
            )),
            "extraction_timestamp": "2025-01-25T18:00:00Z"
        }

    # 保存文件 - 固定输出文件名为 banks_balance_result.yaml
    base_dir = os.path.dirname(args.output) if os.path.dirname(args.output) else os.getcwd()
    filename = "banks_balance_result.yaml"
    abs_path = os.path.join(base_dir, filename)
    with open(abs_path, "w") as f:
        yaml.dump(swagger, f)

    print(f"✅ 增强版OpenAPI规范已保存到: {abs_path}")


def print_balance_extraction_summary(balance_data_cache):
    """打印余额提取总结"""
    print("\n" + "="*60)
    print("🎯 余额数据提取总结")
    print("="*60)
    
    for url, balance_data in balance_data_cache.items():
        print(f"\n🏦 API: {url}")
        print(f"   银行: {balance_data.get('bank', 'unknown')}")
        
        balances = balance_data.get('balances', {})
        for currency, amounts in balances.items():
            print(f"   {currency}: {amounts}")
    
    print(f"\n📊 总计: 从 {len(balance_data_cache)} 个API端点提取了余额数据")
    print("="*60)


# 原始功能的辅助函数 (简化版)
def progress_callback(progress):
    console_util.print_progress_bar(progress)

def detect_input_format(file_path):
    har_score = har_archive_heuristic(file_path)
    mitmproxy_score = mitmproxy_dump_file_huristic(file_path)
    if har_score > mitmproxy_score:
        return HarCaptureReader(file_path, progress_callback)
    else:
        return MitmproxyCaptureReader(file_path, progress_callback)

def strip_query_string(path):
    return path.split("?")[0]

def load_or_create_swagger_spec(args, yaml):
    """加载或创建swagger规范"""
    swagger = None
    try:
        base_dir = os.path.dirname(args.output) if os.path.dirname(args.output) else os.getcwd()
        filename = "banks_balance_result.yaml"
        abs_path = os.path.join(base_dir, filename)
        with open(abs_path, "r") as f:
            swagger = yaml.load(f)
    except FileNotFoundError:
        print("No existing swagger file found. Creating new one.")
    
    if swagger is None:
        swagger = ruamel.yaml.comments.CommentedMap({
            "openapi": "3.0.0",
            "info": {
                "title": args.input + " Enhanced Mitmproxy2Swagger",
                "version": "1.0.0",
                "description": "Enhanced with balance data extraction capabilities"
            },
        })
    
    # 初始化基础结构
    if args.api_prefix:
        args.api_prefix = args.api_prefix.rstrip("/")
    else:
        args.api_prefix = ""
    
    if "servers" not in swagger or swagger["servers"] is None:
        swagger["servers"] = []
    
    # 🎯 添加所有检测到的银行API服务器
    if hasattr(args, 'all_api_prefixes'):
        for api_prefix in args.all_api_prefixes:
            if not any(server["url"] == api_prefix for server in swagger["servers"]):
                # 根据域名判断银行类型
                server_description = "API Server"
                if 'bochk.com' in api_prefix:
                    server_description = "中国银行香港 API Server"
                elif 'cmbwinglungbank.com' in api_prefix:
                    server_description = "招商永隆银行 API Server"
                elif 'hsbc' in api_prefix.lower():
                    server_description = "汇丰银行 API Server"
                    
                swagger["servers"].append(
                    {"url": api_prefix, "description": server_description}
                )
    else:
        # 兼容单个前缀的旧逻辑
        if not any(server["url"] == args.api_prefix for server in swagger["servers"]):
            swagger["servers"].append(
                {"url": args.api_prefix, "description": "The default server"}
            )
    
    if "paths" not in swagger or swagger["paths"] is None:
        swagger["paths"] = {}
    
    if "x-path-templates" not in swagger or swagger["x-path-templates"] is None:
        swagger["x-path-templates"] = []
    
    return swagger

def setup_path_templates(swagger):
    """设置路径模板"""
    path_templates = []
    for path in swagger["paths"]:
        path_templates.append(path)
    
    if "x-path-templates" in swagger and swagger["x-path-templates"] is not None:
        for path in swagger["x-path-templates"]:
            path_templates.append(path)
    
    def path_to_regex(path):
        path = re.escape(path)
        path = path.replace(r"\{", "(?P<")
        path = path.replace(r"\}", ">[^/]+)")
        path = path.replace(r"\*", ".*")
        return "^" + path + "$"
    
    path_template_regexes = [re.compile(path_to_regex(path)) for path in path_templates]
    return path_templates, path_template_regexes

def find_path_template_match(path, path_template_regexes):
    """查找匹配的路径模板"""
    for i, path_template_regex in enumerate(path_template_regexes):
        if path_template_regex.match(path):
            return i
    return None

def ensure_swagger_path_exists(swagger, path_template, method):
    """确保swagger路径存在"""
    if path_template not in swagger["paths"]:
        swagger["paths"][path_template] = {}
    
    if method not in swagger["paths"][path_template]:
        swagger["paths"][path_template][method] = {
            "summary": swagger_util.path_template_to_endpoint_name(method, path_template),
            "responses": {},
        }

def process_request_data(swagger, path_template, method, req, url, args):
    """处理请求数据"""
    params = swagger_util.url_to_params(url, path_template)
    
    if args.headers:
        headers_request = swagger_util.request_to_headers(req.get_request_headers())
        if headers_request and len(headers_request) > 0:
            if "parameters" not in swagger["paths"][path_template][method]:
                swagger["paths"][path_template][method]["parameters"] = []
            swagger["paths"][path_template][method]["parameters"].extend(headers_request)
    
    if params and len(params) > 0:
        if "parameters" not in swagger["paths"][path_template][method]:
            swagger["paths"][path_template][method]["parameters"] = []
        swagger["paths"][path_template][method]["parameters"].extend(params)

def ensure_default_response(swagger, path_template, method, req):
    """确保存在默认响应"""
    if len(swagger["paths"][path_template][method]["responses"]) == 0:
        swagger["paths"][path_template][method]["responses"]["200"] = {
            "description": "OK",
            "content": {},
        }

def auto_detect_api_prefixes(capture_reader):
    """自动检测所有银行API前缀"""
    from urllib.parse import urlparse
    import collections
    
    # 收集所有URL的基础部分
    base_urls = collections.Counter()
    bank_prefixes = []
    
    try:
        # 临时遍历请求来检测URL模式
        temp_requests = []
        for req in capture_reader.captured_requests():
            full_url = req.get_url()
            if full_url:
                parsed = urlparse(full_url)
                # 构建基础URL (协议 + 域名)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                base_urls[base_url] += 1
                temp_requests.append(req)
                
                # 限制检查数量以提高性能
                if len(temp_requests) > 200:
                    break
        
        if base_urls:
            # 识别银行相关的域名
            bank_keywords = ['bank', 'bochk', 'cmbwinglungbank', 'hsbc', 'dbs', 'financial']
            
            for base_url, count in base_urls.most_common():
                domain = urlparse(base_url).netloc.lower()
                if any(keyword in domain for keyword in bank_keywords):
                    bank_prefixes.append(base_url)
                    print(f"🏦 检测到银行API前缀: {base_url} ({count} 个请求)")
            
            if bank_prefixes:
                return bank_prefixes
            else:
                # 如果没找到银行域名，返回最常见的前缀
                most_common_base = base_urls.most_common(1)[0][0]
                return [most_common_base]
        else:
            # 默认返回通用前缀
            return ["https://api.example.com"]
            
    except Exception as e:
        print(f"⚠️  API前缀自动检测失败: {e}")
        return ["https://api.example.com"]

def handle_flow_read_error(e, args, capture_reader):
    """处理流读取错误"""
    print(f"Flow file corrupted: {e}")
    traceback.print_exception(*sys.exc_info())
    print(f"{console_util.ANSI_RED}Failed to parse the input file as '{capture_reader.name()}'. ")
    if not args.format:
        print("It might happen that the input format as incorrectly detected. Please try using '--format flow' or '--format har' to specify the input format.{console_util.ANSI_RESET}")
    sys.exit(1)


if __name__ == "__main__":
    enhanced_main() 