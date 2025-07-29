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
    parser.add_argument("-p", "--api-prefix", help="The api prefix", required=True)
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

    # 加载或创建swagger规范  
    swagger = load_or_create_swagger_spec(args, yaml)
    
    # 处理路径模板
    path_templates, path_template_regexes = setup_path_templates(swagger)
    new_path_templates = []

    try:
        balance_data_cache = {}  # 缓存提取的余额数据
        
        for req in capture_reader.captured_requests():
            # 基础URL和路径处理
            url = req.get_matching_url(args.api_prefix)
            if url is None:
                continue
                
            method = req.get_method().lower()
            path = strip_query_string(url).removeprefix(args.api_prefix)
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
                            
                            # 如果启用了明文展示
                            if args.balance_plaintext and args.examples:
                                # ⚠️ 重要：传递实际提取的余额数据，不使用任何硬编码数据
                                balance_examples = get_balance_examples_for_endpoint(url, balance_data)
                                if balance_examples:
                                    resp_data_to_set['content'][content_type_to_use]['x-balance-examples'] = balance_examples

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


def save_enhanced_swagger(swagger, new_path_templates, args, yaml, balance_data_cache):
    """保存增强的swagger文件"""
    
    # 添加新发现的路径模板
    if new_path_templates:
        # 🎯 修改：检查路径是否包含余额数据，如果包含则不加ignore前缀
        processed_templates = []
        for path in new_path_templates:
            # 检查是否有URL包含此路径且在余额数据缓存中
            has_balance_data = any(path in url for url in balance_data_cache.keys())
            if has_balance_data:
                # 包含余额数据的路径不加ignore前缀，让其被正常处理
                processed_templates.append(path)
                print(f"✅ 余额API路径将被正常处理: {path}")
            else:
                # 不包含余额数据的路径加ignore前缀
                processed_templates.append(f"ignore:{path}")
        
        swagger["x-path-templates"].extend(processed_templates)

    # 🎯 添加余额数据元信息
    if balance_data_cache:
        swagger["x-balance-extraction-info"] = {
            "extracted_endpoints": len(balance_data_cache),
            "supported_banks": list(set(
                data.get('bank', 'unknown') for data in balance_data_cache.values()
            )),
            "extraction_timestamp": "2025-01-25T18:00:00Z"
        }

    # 保存文件
    base_dir = os.getcwd()
    relative_path = args.output
    abs_path = os.path.join(base_dir, relative_path)
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
        base_dir = os.getcwd()
        relative_path = args.output
        abs_path = os.path.join(base_dir, relative_path)
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
    args.api_prefix = args.api_prefix.rstrip("/")
    
    if "servers" not in swagger or swagger["servers"] is None:
        swagger["servers"] = []
    
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