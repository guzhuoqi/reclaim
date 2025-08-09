#!/usr/bin/env python3
"""
分析抓包文件中特定字段的匹配情况
Analyze field matches in captured traffic files
"""

import json
import os
import sys
from pathlib import Path
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException
import re
from collections import defaultdict, Counter

def analyze_response_content(content: str, patterns: dict) -> dict:
    """分析响应内容中的模式匹配"""
    matches = {}

    for field_name, pattern_info in patterns.items():
        pattern_type = pattern_info.get('type', 'contains')
        pattern_value = pattern_info.get('value', '')
        invert = pattern_info.get('invert', False)

        if pattern_type == 'contains':
            # 移除引号进行匹配
            search_value = pattern_value.strip('"')
            found = search_value in content

            if invert:
                found = not found

            matches[field_name] = {
                'found': found,
                'pattern': pattern_value,
                'type': pattern_type,
                'invert': invert
            }

            # 如果找到匹配，尝试提取上下文
            if found and not invert:
                # 查找包含该字段的JSON片段
                json_contexts = extract_json_contexts(content, search_value)
                if json_contexts:
                    matches[field_name]['contexts'] = json_contexts[:3]  # 最多3个上下文

    return matches

def extract_json_contexts(content: str, field_name: str) -> list:
    """提取包含指定字段的JSON上下文"""
    contexts = []

    # 尝试解析整个响应为JSON
    try:
        json_data = json.loads(content)
        contexts.extend(find_field_in_json(json_data, field_name))
    except:
        # 如果不是完整JSON，尝试查找JSON片段
        json_pattern = r'\{[^{}]*"' + re.escape(field_name) + r'"[^{}]*\}'
        matches = re.finditer(json_pattern, content)

        for match in matches:
            try:
                json_fragment = json.loads(match.group())
                contexts.append(json_fragment)
            except:
                # 如果JSON片段无效，保存原始文本
                contexts.append(match.group())

        if len(contexts) == 0:
            # 查找简单的键值对
            simple_pattern = r'"' + re.escape(field_name) + r'":\s*"[^"]*"'
            simple_matches = re.findall(simple_pattern, content)
            contexts.extend(simple_matches[:3])

    return contexts

def find_field_in_json(data, field_name: str, path: str = "") -> list:
    """递归查找JSON中的字段"""
    results = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            if key == field_name:
                results.append({
                    'path': current_path,
                    'value': value,
                    'context': {k: v for k, v in data.items() if k != field_name}
                })

            if isinstance(value, (dict, list)):
                results.extend(find_field_in_json(value, field_name, current_path))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_path = f"{path}[{i}]" if path else f"[{i}]"
            if isinstance(item, (dict, list)):
                results.extend(find_field_in_json(item, field_name, current_path))

    return results

def analyze_mitm_file(file_path: str, patterns: dict) -> dict:
    """分析单个mitm文件"""
    print(f"\n🔍 分析文件: {file_path}")

    results = {
        'file_path': file_path,
        'total_flows': 0,
        'analyzed_responses': 0,
        'field_matches': defaultdict(list),
        'summary': defaultdict(int)
    }

    try:
        with open(file_path, "rb") as f:
            flow_reader = io.FlowReader(f)

            for flow in flow_reader.stream():
                if isinstance(flow, http.HTTPFlow):
                    results['total_flows'] += 1

                    # 分析响应
                    if flow.response and flow.response.content:
                        try:
                            response_text = flow.response.get_text()
                            if response_text:
                                results['analyzed_responses'] += 1

                                # 分析字段匹配
                                matches = analyze_response_content(response_text, patterns)

                                for field_name, match_info in matches.items():
                                    if match_info['found']:
                                        results['field_matches'][field_name].append({
                                            'url': flow.request.pretty_url,
                                            'method': flow.request.method,
                                            'status_code': flow.response.status_code,
                                            'content_type': flow.response.headers.get('content-type', ''),
                                            'match_info': match_info,
                                            'response_size': len(response_text)
                                        })
                                        results['summary'][field_name] += 1
                        except Exception as e:
                            print(f"   ⚠️  响应解析错误: {e}")

    except FlowReadException as e:
        print(f"   ❌ 文件读取错误: {e}")
        return None
    except Exception as e:
        print(f"   ❌ 分析错误: {e}")
        return None

    print(f"   📊 总流量: {results['total_flows']}, 分析响应: {results['analyzed_responses']}")
    for field_name, count in results['summary'].items():
        print(f"   🎯 {field_name}: {count} 次匹配")

    return results

def main():
    # 定义要分析的字段模式
    patterns = {
        'currency': {
            'type': 'contains',
            'value': '"currency"',
            'invert': False
        },
        'phone': {
            'type': 'contains',
            'value': '"phone"',
            'invert': False
        },
        'email': {
            'type': 'contains',
            'value': '"email"',
            'invert': False
        }
    }

    print("🔍 抓包文件字段匹配分析")
    print("=" * 50)
    print("分析字段:")
    for field_name, pattern_info in patterns.items():
        print(f"  • {field_name}: {pattern_info['value']}")
    print()

    # 查找所有mitm文件
    current_dir = Path(__file__).parent
    mitm_files = []

    # 在temp目录中查找
    temp_dir = current_dir / 'temp'
    if temp_dir.exists():
        mitm_files.extend(temp_dir.glob('*.mitm'))

    # 在testdata目录中查找
    testdata_dir = current_dir.parent / 'testdata'
    if testdata_dir.exists():
        mitm_files.extend(testdata_dir.glob('*.mitm'))

    if not mitm_files:
        print("❌ 未找到mitm文件")
        return

    print(f"📁 找到 {len(mitm_files)} 个mitm文件")

    # 分析所有文件
    all_results = []
    overall_summary = defaultdict(int)

    for mitm_file in sorted(mitm_files):
        result = analyze_mitm_file(str(mitm_file), patterns)
        if result:
            all_results.append(result)
            for field_name, count in result['summary'].items():
                overall_summary[field_name] += count

    # 生成总结报告
    print("\n" + "=" * 50)
    print("📊 总结报告")
    print("=" * 50)

    total_flows = sum(r['total_flows'] for r in all_results)
    total_responses = sum(r['analyzed_responses'] for r in all_results)

    print(f"📁 分析文件数: {len(all_results)}")
    print(f"📊 总流量数: {total_flows}")
    print(f"📄 分析响应数: {total_responses}")
    print()

    print("🎯 字段匹配统计:")
    for field_name in patterns.keys():
        count = overall_summary[field_name]
        percentage = (count / total_responses * 100) if total_responses > 0 else 0
        print(f"  • {field_name}: {count} 次匹配 ({percentage:.1f}%)")

    # 保存详细结果
    try:
        import pandas as pd
        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
    except:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_file = current_dir / 'data' / f'field_match_analysis_{timestamp}.json'

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'analysis_timestamp': timestamp,
            'patterns': patterns,
            'overall_summary': dict(overall_summary),
            'total_files': len(all_results),
            'total_flows': total_flows,
            'total_responses': total_responses,
            'detailed_results': all_results
        }, f, indent=2, ensure_ascii=False)

    print(f"\n💾 详细结果已保存到: {output_file}")

if __name__ == "__main__":
    main()
