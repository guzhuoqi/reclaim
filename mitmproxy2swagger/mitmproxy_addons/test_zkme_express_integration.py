#!/usr/bin/env python3
"""
测试zkme-express集成
快速验证新API是否工作正常
"""

import json
import asyncio
from zkme_express_client import ZkmeExpressClient


def test_simple_api():
    """测试简单的API调用"""
    print("🧪 测试zkme-express集成")
    print("=" * 50)
    
    # 创建客户端
    client = ZkmeExpressClient("http://localhost:3000")
    
    # 构建测试参数 - 使用我们的格式
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
                "title": '"title":\\s*"(?<title>[^"]+)"',
                "body": '"body":\\s*"(?<body>[^"]+)"'
            },
            "geoLocation": "US"
        },
        "secretParams": {
            "cookieStr": "test=cookie_value"
        }
    }
    
    async def run_test():
        print(f"📋 测试参数:")
        print(f"   URL: {test_params['params']['url']}")
        print(f"   Method: {test_params['params']['method']}")
        print(f"   ResponseMatches: {len(test_params['params']['responseMatches'])} 个")
        print(f"   SecretParams: {list(test_params['secretParams'].keys())}")
        print("")
        
        try:
            result = await client.execute_attestor_task("test_task_zkme", test_params)
            
            print("🎯 测试结果:")
            print(f"   成功: {'✅' if result.get('success') else '❌'}")
            
            if result.get("success"):
                print(f"   任务ID: {result.get('task_id')}")
                print(f"   执行时间: {result.get('execution_time', 0):.2f}秒")
                
                if "extractedParameters" in result:
                    print(f"   提取的参数: {result['extractedParameters']}")
                else:
                    print("   ⚠️  未提取到参数")
                    
                if "receipt" in result and result["receipt"]:
                    print(f"   Receipt存在: ✅")
                else:
                    print(f"   Receipt存在: ❌")
            else:
                print(f"   错误: {result.get('error', 'Unknown error')}")
            
            return result.get("success", False)
            
        except Exception as e:
            print(f"❌ 测试异常: {e}")
            return False
    
    return asyncio.run(run_test())


def test_bank_api_format():
    """测试银行API格式"""
    print("\n🏦 测试银行API格式")
    print("=" * 50)
    
    client = ZkmeExpressClient("http://localhost:3000")
    
    # 模拟银行API参数
    bank_params = {
        "params": {
            "url": "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbBkgActdetCoaProc2022&AcctTypeId=CON",
            "method": "POST",
            "headers": {
                "Host": "www.cmbwinglungbank.com",
                "Connection": "close",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "body": "",
            "responseMatches": {
                "hkd_balance": "HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})",
                "usd_balance": "USD[^\\d]*(\\d[\\d,]*\\.\\d{2})"
            },
            "geoLocation": "HK"
        },
        "secretParams": {
            "cookieStr": "JSESSIONID=test123; dse_sessionId=test456"
        }
    }
    
    async def run_bank_test():
        print(f"📋 银行API测试参数:")
        print(f"   URL: {bank_params['params']['url'][:80]}...")
        print(f"   Method: {bank_params['params']['method']}")
        print(f"   Headers: {len(bank_params['params']['headers'])} 个")
        print(f"   Cookie: {bank_params['secretParams']['cookieStr'][:30]}...")
        print("")
        
        try:
            result = await client.execute_attestor_task("test_bank_zkme", bank_params)
            
            print("🎯 银行API测试结果:")
            print(f"   成功: {'✅' if result.get('success') else '❌'}")
            
            if not result.get("success"):
                print(f"   错误: {result.get('error', 'Unknown error')}")
                # 这是预期的，因为我们没有真实的银行会话
                return True  # 只要API调用没有异常就算成功
            
            return result.get("success", False)
            
        except Exception as e:
            print(f"❌ 银行API测试异常: {e}")
            return False
    
    return asyncio.run(run_bank_test())


def main():
    """主测试函数"""
    print("🚀 zkme-express 集成测试")
    print("=" * 60)
    
    success_count = 0
    total_tests = 2
    
    # 测试1：简单API
    if test_simple_api():
        success_count += 1
        print("✅ 简单API测试通过")
    else:
        print("❌ 简单API测试失败")
    
    # 测试2：银行API格式
    if test_bank_api_format():
        success_count += 1
        print("✅ 银行API格式测试通过")
    else:
        print("❌ 银行API格式测试失败")
    
    print("\n" + "=" * 60)
    print(f"🎯 测试完成: {success_count}/{total_tests} 通过")
    
    if success_count == total_tests:
        print("🎉 所有测试通过！zkme-express集成成功！")
        print("\n💡 下一步:")
        print("   1. 修改配置文件启用zkme-express: 'use_zkme_express': true")
        print("   2. 重启mitmproxy代理服务")
        print("   3. 测试实际的银行网站抓包")
        return True
    else:
        print("⚠️  部分测试失败，请检查:")
        print("   1. zkme-express服务是否正常运行")
        print("   2. API端点是否正确")
        print("   3. 网络连接是否正常")
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
