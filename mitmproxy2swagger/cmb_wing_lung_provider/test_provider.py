#!/usr/bin/env python3
"""
招商永隆银行 Provider 测试
测试基于验证过的数据和逻辑
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cmb_wing_lung_provider import CMBWingLungProvider, ReclaimCMBWingLungProvider


def test_provider_initialization():
    """测试Provider初始化"""
    provider = CMBWingLungProvider()
    
    assert provider.bank_name == "招商永隆银行"
    assert provider.api_base == "https://www.cmbwinglungbank.com/ibanking"
    assert "HKD" in provider.api_config['supported_currencies']
    assert "USD" in provider.api_config['supported_currencies']
    assert "CNY" in provider.api_config['supported_currencies']
    
    print("✅ Provider初始化测试通过")


def test_api_config_validation():
    """验证API配置的完整性"""
    provider = CMBWingLungProvider()
    config = provider.api_config
    
    # 验证必需的endpoint配置
    assert config['login_endpoint'] == "/WlbLogonServlet"
    assert config['balance_endpoint'] == "/McpCSReqServlet"
    assert config['balance_operation'] == "NbBkgActdetCoaProc2022"
    
    # 验证账户类型配置
    expected_account_types = ["CON", "DDA", "SAV", "FDA", "CUR", "MEC"]
    for account_type in expected_account_types:
        assert account_type in config['account_types']
    
    print("✅ API配置验证测试通过")


def test_amount_string_parsing():
    """测试金额字符串解析 - 基于验证数据"""
    provider = CMBWingLungProvider()
    
    # 基于实际验证的数据格式
    assert provider._parse_amount_string("7,150.98") == 7150.98
    assert provider._parse_amount_string("30.75") == 30.75
    assert provider._parse_amount_string("0.00") == 0.00
    assert provider._parse_amount_string("1,234,567.89") == 1234567.89
    
    # 异常情况处理
    assert provider._parse_amount_string("") == 0.0
    assert provider._parse_amount_string("invalid") == 0.0
    
    print("✅ 金额字符串解析测试通过")


def test_balance_data_validation():
    """测试余额数据验证逻辑"""
    provider = CMBWingLungProvider()
    
    # 有效数据测试 - 基于实际验证结果
    valid_data = {
        "balances": {
            "HKD": ["7,150.98"],
            "USD": ["30.75"],
            "CNY": ["0.00"]
        }
    }
    validation = provider.validate_balance_data(valid_data)
    assert validation['valid'] == True
    assert validation['confidence'] == 1.0
    assert len(validation['issues']) == 0
    
    # 无效数据测试
    invalid_data = {
        "balances": {
            "HKD": ["invalid_amount"],
            "UNKNOWN_CURRENCY": ["100.00"]
        }
    }
    validation = provider.validate_balance_data(invalid_data)
    assert validation['valid'] == False
    assert validation['confidence'] < 1.0
    assert len(validation['issues']) > 0
    
    print("✅ 余额数据验证测试通过")


def test_reclaim_provider_initialization():
    """测试Reclaim Provider初始化"""
    provider = ReclaimCMBWingLungProvider()
    
    assert provider.provider_id == "cmb_wing_lung_balance"
    assert provider.provider_version == "1.0.0"
    assert "account_balance" in provider.reclaim_config['supported_claims']
    assert provider.reclaim_config['verification_method'] == "zktls"
    
    print("✅ Reclaim Provider初始化测试通过")


def test_session_id_extraction():
    """测试session ID提取的正则模式"""
    provider = CMBWingLungProvider()
    
    # 测试用例1: 标准JSON格式
    html1 = '{"dse_sessionId": "ABC123XYZ"}'
    session_id1 = provider._extract_session_id(html1)
    assert session_id1 == "ABC123XYZ", f"Expected ABC123XYZ, got {session_id1}"
    
    # 测试用例2: URL参数格式
    html2 = 'sessionId=DEF456UVW&other=param'
    session_id2 = provider._extract_session_id(html2)
    assert session_id2 == "DEF456UVW", f"Expected DEF456UVW, got {session_id2}"
    
    print("✅ Session ID提取测试通过")


if __name__ == "__main__":
    print("🧪 运行招商永隆银行 Provider 测试")
    print("📊 基于验证数据: HKD 7,150.98, USD 30.75, CNY 0.00")
    print("🔧 测试覆盖: 初始化、API配置、数据验证、错误处理")
    print()
    
    try:
        test_provider_initialization()
        test_api_config_validation()
        test_amount_string_parsing()
        test_balance_data_validation()
        test_reclaim_provider_initialization()
        test_session_id_extraction()
        
        print()
        print("🎉 所有测试通过！")
        print("✅ Provider已准备就绪，可用于生产环境")
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        print("💡 请检查provider实现")
        sys.exit(1) 