import { createClaimOnAttestor } from '@reclaimprotocol/attestor-core';
import { Wallet } from 'ethers';

/**
 * 调用 Reclaim Attestor 获取银行余额 Claim 示例
 * 
 * 本示例演示如何通过 Attestor 验证CMB永隆银行的HKD账户余额
 * 使用真实浏览器 User-Agent 和完整 headers 来通过银行的安全检查
 */

async function getBankBalanceClaimFromAttestor() {
  try {
    console.log('🏦 开始调用 Reclaim Attestor 获取银行余额 Claim');
    console.log('=' .repeat(60));

    // ========== 1. 配置参数 ==========
    
    // 用户私钥（实际使用时应从安全存储获取）
    const userPrivateKey = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const wallet = new Wallet(userPrivateKey);
    const userAddress = wallet.address;
    
    console.log('👤 用户地址:', userAddress);

    // 任务信息
    const taskId = '53'; // 使用现有任务ID
    const attestorHost = 'wss://devint-reclaim0.mechain.tech/ws'; // Attestor WebSocket地址
    const attestorAddress = '0xaef2Ba08B0f836c81ed975452507825B5497e62f'; // Attestor地址
    
    console.log('📋 任务ID:', taskId);
    console.log('🔗 Attestor主机:', attestorHost);
    console.log('📍 Attestor地址:', attestorAddress);

    // ========== 2. 银行API配置 ==========
    
    // 从之前的成功请求中获取的真实银行会话信息
    const bankSessionId = 'DKGNBKFJCHBMGMEKHECBDIHDEHHUARHDHVAQEUHW';
    const originalTimestamp = '1753673623980'; // 使用原始时间戳
    
    // 构建完整的银行API URL（使用原始参数）
    const bankApiUrl = `https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbBkgActdetCoaProc2022&dse_processorState=initial&dse_nextEventName=start&dse_sessionId=${bankSessionId}&mcp_language=cn&dse_pageId=1&dse_parentContextName=&mcp_timestamp=${originalTimestamp}&AcctTypeIds=DDA,CUR,SAV,FDA,CON,MEC&AcctTypeId=CON&RequestType=D&selectedProductKey=CON`;

    console.log('🏦 银行API URL:', bankApiUrl);
    console.log('🔑 会话ID:', bankSessionId);

    // ========== 3. 配置 Provider 参数 ==========
    
    // HTTP Provider 参数 - 请求银行余额API
    const providerParams = {
      method: 'POST',
      url: bankApiUrl,
      geoLocation: 'HK', // 香港地区
      // POST请求体（空，因为参数都在URL中）
      body: '',
      // 匹配HKD余额的正则表达式
      responseMatches: [{
        type: 'regex',
        value: 'HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})'
      }],
      // 隐藏敏感信息，只显示余额
      responseRedactions: [{
        regex: 'HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})'
      }]
    };

    // ========== 4. 真实浏览器信息配置 ==========
    
    // 秘密参数 - 使用真实浏览器的完整headers
    const secretParams = {
      // 使用真实的银行登录Cookie
      cookieStr: `JSESSIONID=0000Iq3duEGwXQ_t98tpsTIkp4U:1i8ioc86i; dse_sessionId=${bankSessionId}; Path=/; HttpOnly`,
      
              // 完整的浏览器headers（模拟真实用户访问）
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
          'Accept': '*/*',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
          'Accept-Encoding': 'gzip, deflate, br, zstd',
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
          'Content-Length': '0',
          'Connection': 'keep-alive',
          'Host': 'www.cmbwinglungbank.com',
          'Origin': 'https://www.cmbwinglungbank.com',
          'Referer': 'https://www.cmbwinglungbank.com/ibanking/login.do',
          'Sec-Ch-Ua': '"Chromium";v="138", "Not=A?Brand";v="8", "Google Chrome";v="138"',
          'Sec-Ch-Ua-Mobile': '?0',
          'Sec-Ch-Ua-Platform': '"macOS"',
          'Sec-Fetch-Dest': 'empty',
          'Sec-Fetch-Mode': 'cors',
          'Sec-Fetch-Site': 'same-origin',
          'X-Requested-With': 'XMLHttpRequest',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache'
        }
    };

    // 上下文信息
    const context = {
      taskId: taskId,
      timestamp: new Date().toISOString(),
      description: 'CMB Wing Lung Bank HKD Balance Verification',
      bankInfo: {
        bank: 'CMB Wing Lung Bank',
        accountType: 'CON', // 活期账户
        currency: 'HKD',
        operation: 'Balance Query'
      }
    };

    console.log('📝 Provider:', 'http (银行专用配置)');
    console.log('💰 查询类型: HKD活期账户余额');
    console.log('🌍 地理位置: 香港 (HK)');

    // ========== 5. 调用 Attestor ==========
    
    console.log('\n📡 正在调用 Attestor 获取银行余额...');
    console.log('⏳ 请稍候，正在建立安全连接...');
    
    const result = await createClaimOnAttestor({
      // Provider 配置
      name: 'http',
      params: providerParams,
      secretParams: secretParams,
      context: context,
      
      // 用户签名配置
      ownerPrivateKey: userPrivateKey,
      
      // Attestor 连接配置
      client: {
        url: attestorHost
      }
    });

    // ========== 6. 处理银行余额结果 ==========

    if (result.claim) {
      console.log('\n✅ 成功获取银行余额 Claim!');
      console.log('🏆 银行验证完成!');
      console.log('=' .repeat(50));
      
      console.log('📄 Claim 基本信息:');
      console.log('  - Claim ID:', result.claim.identifier);
      console.log('  - Provider:', result.claim.provider);
      console.log('  - Owner:', result.claim.owner);
      console.log('  - 时间戳:', new Date(result.claim.timestampS * 1000).toISOString());

      // 解析银行余额数据
      const extractedParams = JSON.parse(result.claim.context).extractedParameters;
      if (extractedParams) {
        console.log('\n💰 银行余额信息:');
        Object.entries(extractedParams).forEach(([key, value]) => {
          if (key.includes('balance') || key.includes('amount') || /\d+\.\d{2}/.test(value)) {
            console.log(`  💵 ${key}: HKD ${value}`);
          } else {
            console.log(`  📋 ${key}: ${value}`);
          }
        });
      }

      console.log('\n🔐 验证签名信息:');
      console.log('  - Attestor地址:', result.signatures.attestorAddress);
      console.log('  - Claim签名长度:', result.signatures.claimSignature.length, 'bytes');
      console.log('  - 结果签名长度:', result.signatures.resultSignature.length, 'bytes');

      // ========== 7. 银行业务数据 ==========
      console.log('\n🏦 银行业务验证数据:');
      console.log('=' .repeat(60));
      
      const bankVerificationData = {
        success: true,
        bank: 'CMB Wing Lung Bank',
        verificationTime: new Date().toISOString(),
        sessionId: bankSessionId,
        accountType: 'HKD Current Account (CON)',
        verificationMethod: 'Zero-Knowledge TLS Proof',
        taskId: taskId,
        attestorAddress: result.signatures.attestorAddress,
        claimData: {
          identifier: result.claim.identifier,
          provider: result.claim.provider,
          owner: result.claim.owner,
          timestamp: result.claim.timestampS,
          context: result.claim.context
        },
        signatures: {
          claimSignature: result.signatures.claimSignature,
          resultSignature: result.signatures.resultSignature
        }
      };
      
      console.log('📊 验证数据 (JSON格式):');
      console.log(JSON.stringify(bankVerificationData, null, 2));

      console.log('\n🎉 银行余额验证成功完成!');
      return bankVerificationData;

    } else {
      console.log('\n❌ 未能获取银行余额 Claim');
      console.log('🔍 可能的原因:');
      console.log('  - 银行会话已过期');
      console.log('  - 网络连接问题');
      console.log('  - Attestor节点繁忙');
      
      return null;
    }

  } catch (error) {
    console.error('\n💥 调用过程中发生错误:');
    console.error('错误详情:', error.message);
    
    // 详细错误分析
    if (error.message.includes('Channel Handler')) {
      console.error('🔍 分析: 银行服务器拒绝了请求 - 可能是User-Agent或headers不匹配');
    } else if (error.message.includes('session')) {
      console.error('🔍 分析: 会话相关错误 - 可能需要重新登录银行');
    } else if (error.message.includes('network') || error.message.includes('timeout')) {
      console.error('🔍 分析: 网络连接问题 - 请检查网络状态');
    }
    
    throw error;
  }
}

// ========== 8. 主执行函数 ==========

async function main() {
  console.log('🚀 启动银行余额验证示例');
  console.log('🏦 目标: CMB永隆银行 HKD活期账户');
  console.log('🔒 方法: Zero-Knowledge TLS Proof');
  console.log('=' .repeat(60));
  
  try {
    const result = await getBankBalanceClaimFromAttestor();
    
    if (result) {
      console.log('\n✅ 任务完成! 银行余额验证成功');
      process.exit(0);
    } else {
      console.log('\n❌ 任务失败! 未能完成银行余额验证');
      process.exit(1);
    }
    
  } catch (error) {
    console.error('\n💥 程序执行失败:', error.message);
    process.exit(1);
  }
}

// 如果直接执行此文件，则运行主函数
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { getBankBalanceClaimFromAttestor }; 