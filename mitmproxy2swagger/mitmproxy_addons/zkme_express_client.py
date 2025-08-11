#!/usr/bin/env python3
"""
ZkmeExpress客户端
调用zkme-express的generate-receipt-for-python API
完全使用我们当前的参数格式，无需转换
"""

import json
import requests
import time
from typing import Dict, Any, Optional


class ZkmeExpressClient:
    """ZkmeExpress API客户端"""
    
    def __init__(self, base_url: str = "https://test-exp.bitkinetic.com"):
        self.base_url = base_url.rstrip('/')
        self.timeout = 180  # 3分钟超时
    
    async def execute_attestor_task(self, task_id: str, attestor_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行attestor任务，调用zkme-express的新API
        
        Args:
            task_id: 任务ID
            attestor_params: attestor参数，格式与我们当前使用的完全一致
            
        Returns:
            执行结果字典
        """
        try:
            start_time = time.time()
            print(f"🚀 开始执行Attestor任务 {task_id} (通过zkme-express API)...")
            
            # 提取参数
            params = attestor_params.get("params", {})
            secret_params = attestor_params.get("secretParams", {})
            
            # 构建请求数据 - 完全使用我们的格式，无需转换
            request_data = {
                "params": params,
                "secretParams": secret_params,
                "attestor": "local",  # 使用本地attestor
                "privateKey": "0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89"  # 测试私钥
            }
            
            print(f"🔍 调用zkme-express API:")
            print(f"   URL: {self.base_url}/reclaim/generate-receipt-for-python")
            print(f"   params.url: {params.get('url', '')[:100]}...")
            print(f"   params.method: {params.get('method', '')}")
            print(f"   secretParams keys: {list(secret_params.keys())}")
            
            # 发送HTTP请求
            response = requests.post(
                f"{self.base_url}/reclaim/generate-receipt-for-python",
                json=request_data,
                timeout=self.timeout,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "mitmproxy-attestor-addon/1.0"
                }
            )
            
            execution_time = time.time() - start_time
            
            print(f"   HTTP状态码: {response.status_code}")
            print(f"   执行时间: {execution_time:.2f}秒")
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    print(f"   响应解析成功: code={response_data.get('code')}")
                    
                    if response_data.get("code") == 80000000:
                        # 成功响应
                        api_result = response_data.get("data", {})
                        
                        if api_result.get("success"):
                            print(f"   ✅ Attestor执行成功!")
                            
                            # 构建与原本一致的响应格式
                            result = {
                                "success": True,
                                "receipt": api_result.get("receipt"),
                                "task_id": task_id,
                                "execution_time": execution_time,
                                "timestamp": api_result.get("timestamp")
                            }
                            
                            # 尝试提取extractedParameters
                            receipt = api_result.get("receipt", {})
                            if receipt.get("claim") and receipt["claim"].get("context"):
                                try:
                                    context = receipt["claim"]["context"]
                                    if isinstance(context, str):
                                        context = json.loads(context)
                                    if context.get("extractedParameters"):
                                        result["extractedParameters"] = context["extractedParameters"]
                                        print(f"   提取的参数: {context['extractedParameters']}")
                                except Exception as parse_error:
                                    print(f"   解析context失败: {parse_error}")
                            
                            return result
                        else:
                            # API调用成功但attestor执行失败
                            error_msg = api_result.get("error", "Unknown error")
                            print(f"   ❌ Attestor执行失败: {error_msg}")
                            return {
                                "success": False,
                                "error": error_msg,
                                "task_id": task_id,
                                "execution_time": execution_time
                            }
                    else:
                        # API调用失败
                        error_msg = response_data.get("msg", "API call failed")
                        print(f"   ❌ API调用失败: {error_msg}")
                        return {
                            "success": False,
                            "error": f"API Error: {error_msg}",
                            "task_id": task_id,
                            "execution_time": execution_time
                        }
                        
                except json.JSONDecodeError as e:
                    error_msg = f"JSON解析失败: {e}"
                    print(f"   ❌ {error_msg}")
                    return {
                        "success": False,
                        "error": error_msg,
                        "task_id": task_id,
                        "execution_time": execution_time
                    }
            else:
                # HTTP请求失败
                error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                print(f"   ❌ HTTP请求失败: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg,
                    "task_id": task_id,
                    "execution_time": execution_time
                }
                
        except requests.exceptions.Timeout:
            error_msg = f"请求超时 ({self.timeout}秒)"
            print(f"   ⏰ {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "task_id": task_id
            }
        except requests.exceptions.RequestException as e:
            error_msg = f"网络请求异常: {e}"
            print(f"   ❌ {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "task_id": task_id
            }
        except Exception as e:
            error_msg = f"未知错误: {e}"
            print(f"   ❌ {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "task_id": task_id
            }


# 测试函数
def test_zkme_express_client():
    """测试ZkmeExpress客户端"""
    client = ZkmeExpressClient()
    
    # 构建测试参数
    test_params = {
        "params": {
            "url": "https://jsonplaceholder.typicode.com/posts/1",
            "method": "GET",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            },
            "body": "",
            "responseMatches": {
                "userId": '"userId":\\s*(?<userId>\\d+)',
                "title": '"title":\\s*"(?<title>[^"]+)"'
            }
        },
        "secretParams": {
            "cookieStr": "test=cookie"
        }
    }
    
    import asyncio
    
    async def run_test():
        result = await client.execute_attestor_task("test_task_001", test_params)
        print(f"\n🧪 测试结果:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    asyncio.run(run_test())


if __name__ == "__main__":
    test_zkme_express_client()
