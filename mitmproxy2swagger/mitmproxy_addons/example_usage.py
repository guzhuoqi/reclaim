#!/usr/bin/env python3
"""
HTTP到Attestor转换器使用示例
Example usage of HTTP to Attestor converter
"""

import json
import sys
from pathlib import Path

# 添加当前目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from http_to_attestor_converter import HttpToAttestorConverter


def example_bank_balance_conversion():
    """示例：银行余额查询转换"""
    print("🏦 银行余额查询转换示例")
    print("=" * 50)

    converter = HttpToAttestorConverter()

    # 模拟从mitmproxy抓包得到的银行请求
    bank_request = {
        "url": "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbBkgActdetCoaProc2022&dse_processorState=initial&dse_nextEventName=start&dse_sessionId=BGGLECBCDJHDDUINAXGRELAVAPJJEFJSFXAIBGBT&mcp_language=cn&dse_pageId=1&dse_parentContextName=&mcp_timestamp=1753760475368&AcctTypeIds=DDA,CUR,SAV,FDA,CON,MEC&AcctTypeId=CON&RequestType=D&selectedProductKey=CON",
        "method": "POST",
        "headers": {
            "Host": "www.cmbwinglungbank.com",
            "Connection": "close",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://www.cmbwinglungbank.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbBkgActdetProc2022&dse_processorState=initial&dse_nextEventName=start&dse_sessionId=BGGLECBCDJHDDUINAXGRELAVAPJJEFJSFXAIBGBT&mcp_language=cn&dse_pageId=1&dse_parentContextName=&mcp_timestamp=1753760474422&mcp_funcId=Acm.AcctOverNew",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cookie": "JSESSIONID=0000VLZZZd-gvZlRZzjVUeBIcuv:1a1068cds; dse_sessionId=BGGLECBCDJHDDUINAXGRELAVAPJJEFJSFXAIBGBT"
        },
        "body": ""
    }

    # 定义银行余额的响应匹配模式
    bank_patterns = {
        "hkd_balance": r"HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})",
        "usd_balance": r"USD[^\\d]*(\\d[\\d,]*\\.\\d{2})",
        "total_balance": r"总计[^\\d]*(\\d[\\d,]*\\.\\d{2})"
    }

    # 转换为attestor参数
    attestor_params = converter.convert_raw_request_to_attestor_params(
        url=bank_request["url"],
        method=bank_request["method"],
        headers=bank_request["headers"],
        body=bank_request["body"],
        geo_location="HK",
        custom_patterns=bank_patterns
    )

    print("✅ 转换结果:")
    print(json.dumps(attestor_params, indent=2, ensure_ascii=False))

    print("\n🚀 可执行的命令:")
    command = converter.generate_command_line(attestor_params)
    print(command)

    return attestor_params


def example_api_conversion():
    """示例：API请求转换"""
    print("\n🌐 API请求转换示例")
    print("=" * 50)

    converter = HttpToAttestorConverter()

    # 模拟Binance API请求
    api_request = {
        "url": "https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT",
        "method": "GET",
        "headers": {
            "Host": "api.binance.com",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9"
        },
        "body": ""
    }

    # 定义价格匹配模式
    price_patterns = {
        "eth_price": r'"price":"(\\d+\\.\\d+)"',
        "symbol": r'"symbol":"(\\w+)"'
    }

    # 转换为attestor参数
    attestor_params = converter.convert_raw_request_to_attestor_params(
        url=api_request["url"],
        method=api_request["method"],
        headers=api_request["headers"],
        body=api_request["body"],
        geo_location="US",
        custom_patterns=price_patterns
    )

    print("✅ 转换结果:")
    print(json.dumps(attestor_params, indent=2, ensure_ascii=False))

    print("\n🚀 可执行的命令:")
    command = converter.generate_command_line(attestor_params)
    print(command)

    return attestor_params


def example_custom_patterns():
    """示例：自定义响应模式"""
    print("\n🔧 自定义响应模式示例")
    print("=" * 50)

    converter = HttpToAttestorConverter()

    # 添加自定义模式
    converter.add_response_pattern(
        "transaction_id",
        r"交易号[^\\w]*(\\w{10,20})",
        "交易ID匹配"
    )

    converter.add_response_pattern(
        "timestamp",
        r"时间[^\\d]*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})",
        "时间戳匹配"
    )

    print("📋 所有可用模式:")
    patterns = converter.get_available_patterns()
    for name, desc in patterns.items():
        print(f"  - {name}: {desc}")

    # 使用新模式
    attestor_params = converter.convert_raw_request_to_attestor_params(
        url="https://bank.example.com/api/transaction/history",
        method="GET",
        headers={
            "Authorization": "Bearer token123",
            "Content-Type": "application/json"
        },
        response_patterns=["transaction_id", "timestamp"]
    )

    print("\n✅ 使用自定义模式的转换结果:")
    print(json.dumps(attestor_params, indent=2, ensure_ascii=False))


def example_command_execution_simulation():
    """示例：模拟命令执行"""
    print("\n⚡ 命令执行模拟示例")
    print("=" * 50)

    converter = HttpToAttestorConverter()

    # 简单的请求
    simple_request = {
        "url": "https://httpbin.org/get",
        "method": "GET",
        "headers": {
            "User-Agent": "TestAgent/1.0"
        }
    }

    attestor_params = converter.convert_raw_request_to_attestor_params(
        url=simple_request["url"],
        method=simple_request["method"],
        headers=simple_request["headers"]
    )

    # 生成命令
    command = converter.generate_command_line(attestor_params)

    print("🎯 生成的完整命令:")
    print(command)

    print("\n📝 命令组成部分:")
    name, params_json, secret_params_json = converter.format_for_command_line(attestor_params)
    print(f"  - Name: {name}")
    print(f"  - Params: {params_json[:100]}...")
    print(f"  - Secret Params: {secret_params_json[:100]}...")

    print("\n💡 在实际使用中，你可以这样执行:")
    print("  1. 切换到 attestor-core 目录")
    print("  2. 执行上述命令")
    print("  3. 等待 ZK proof 生成完成")
    print("  4. 获取生成的 claim 对象")


def main():
    """主函数"""
    print("🚀 HTTP到Attestor转换器使用示例")
    print("=" * 60)

    try:
        # 运行所有示例
        example_bank_balance_conversion()
        example_api_conversion()
        example_custom_patterns()
        example_command_execution_simulation()

        print("\n" + "=" * 60)
        print("🎉 所有示例运行完成！")
        print("\n💡 使用提示:")
        print("  1. 根据你的具体需求调整响应匹配模式")
        print("  2. 确保 attestor-core 环境已正确配置")
        print("  3. 在生产环境中使用真实的私钥")
        print("  4. 根据目标API调整地理位置设置")

    except Exception as e:
        print(f"\n❌ 示例运行失败: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
