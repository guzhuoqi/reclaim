import { createClaimOnAttestor } from '@reclaimprotocol/attestor-core';
import { Wallet } from 'ethers';

/**
 * 前端调用 Reclaim Attestor 获取 Claim 示例
 * 
 * 前提条件：
 * 1. 已通过后端 API 创建任务，获得 taskId
 * 2. 已获取到 attestor 节点信息（地址和主机）
 * 3. 用户已准备好私钥用于签名
 */

async function getClaimFromAttestor() {
  try {
    console.log('🚀 开始调用 Reclaim Attestor 获取 Claim');
    console.log('=' .repeat(50));

    // ========== 1. 配置参数 ==========
    
    // 用户私钥（实际使用时应从安全存储获取）
    const userPrivateKey = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const wallet = new Wallet(userPrivateKey);
    const userAddress = wallet.address;
    
    console.log('👤 用户地址:', userAddress);

    // 任务信息（使用固定的已创建任务）
    const taskId = '53'; // 固定使用任务ID 53
    const attestorHost = 'wss://devint-reclaim0.mechain.tech/ws'; // Attestor WebSocket地址
    const attestorAddress = '0xaef2Ba08B0f836c81ed975452507825B5497e62f'; // Attestor地址
    
    console.log('📋 任务ID:', taskId);
    console.log('🔗 Attestor主机:', attestorHost);
    console.log('📍 Attestor地址:', attestorAddress);

    // ========== 2. 配置 Provider 参数 ==========
    
    // HTTP Provider 参数 - 请求 JSONPlaceholder API
    const providerParams = {
      method: 'GET',
      url: 'https://jsonplaceholder.typicode.com/posts/1',
      responseMatches: [{
        type: 'regex',
        value: '"userId":\\s*(?<userId>\\d+)[\\s\\S]*"id":\\s*(?<id>\\d+)[\\s\\S]*"title":\\s*"(?<title>[^"]+)"[\\s\\S]*"body":\\s*"(?<body>[\\s\\S]*?)"'
      }],
      responseRedactions: []
    };

    // 秘密参数（如 headers 等敏感信息）
    const secretParams = {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    };

    // 上下文信息
    const context = {
      taskId: taskId,
      timestamp: new Date().toISOString(),
      description: 'Frontend attestor call example'
    };

    console.log('📝 Provider:', 'http');
    console.log('🔗 目标URL:', providerParams.url);

    // ========== 3. 调用 Attestor ==========
    
    console.log('\n📡 正在调用 Attestor...');
    
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

            // ========== 4. 处理结果 ==========

        if (result.claim) {
          console.log('\n✅ 成功获取 Claim!');
          console.log('📄 Claim 信息:');
          console.log('  - ID:', result.claim.identifier);
          console.log('  - Provider:', result.claim.provider);
          console.log('  - Owner:', result.claim.owner);
          console.log('  - Timestamp:', new Date(result.claim.timestampS * 1000).toISOString());

          // 解析提取的参数
          const extractedParams = JSON.parse(result.claim.context).extractedParameters;
          if (extractedParams) {
            console.log('  - 提取的数据:');
            Object.entries(extractedParams).forEach(([key, value]) => {
              console.log(`    ${key}: ${value}`);
            });
          }

          console.log('\n🔐 签名信息:');
          console.log('  - Attestor地址:', result.signatures.attestorAddress);
          console.log('  - Claim签名长度:', result.signatures.claimSignature.length, 'bytes');
          console.log('  - 结果签名长度:', result.signatures.resultSignature.length, 'bytes');

          // ========== 5. 打印用于后端服务的关键数据 ==========
          console.log('\n📋 用于后端服务的关键数据:');
          console.log('='.repeat(60));
          
          const backendData = {
            taskId: taskId,
            attestorAddress: result.signatures.attestorAddress,
            attestorHost: attestorHost,
            success: true,
            response: {
              claim: result.claim,
              signatures: {
                attestorAddress: result.signatures.attestorAddress,
                claimSignature: Array.from(result.signatures.claimSignature),
                resultSignature: Array.from(result.signatures.resultSignature)
              }
            },
            timestamp: new Date().toISOString()
          };

          // 计算数据大小
          const jsonString = JSON.stringify(backendData);
          const dataSize = new Blob([jsonString]).size;
          const dataSizeKB = (dataSize / 1024).toFixed(2);

          console.log('📤 以下数据应作为入参传递给后端服务进行下一步流程:');
          console.log(`📏 数据大小: ${dataSize} bytes (${dataSizeKB} KB)`);
          console.log('📄 JSON 数据:');
          
          // 自定义格式化，将长数组显示在一行
          const formattedData = JSON.stringify(backendData, (key, value) => {
            if (key === 'claimSignature' || key === 'resultSignature') {
              return `[${value.join(',')}]`;
            }
            return value;
          }, 2);
          
          // 处理数组的格式化显示
          const finalFormatted = formattedData
            .replace(/"(\[[\d,]+\])"/g, '$1') // 移除数组字符串的引号
            .replace(/(\[[\d,]+\])/g, (match) => {
              // 确保数组在一行显示
              return match.replace(/\s+/g, '');
            });
          
          console.log(finalFormatted);

          console.log('\n💡 后续流程说明:');
          console.log('1. 将上述 JSON 数据发送给后端 API');
          console.log('2. 后端可以使用这些数据进行:');
          console.log('   - Claim 验证和存储');
          console.log('   - 链上验证或提交');
          console.log('   - 业务逻辑处理');
          console.log('   - 生成最终的证明或凭证');

          return {
            success: true,
            claim: result.claim,
            signatures: result.signatures,
            backendData: backendData
          };
        } else {
          console.log('❌ 未能获取到 Claim');
          return {
            success: false,
            error: 'No claim returned'
          };
        }

  } catch (error) {
    console.error('❌ 调用失败:', error.message);
    console.error('📍 错误详情:', error);
    
    return {
      success: false,
      error: error.message
    };
  }
}

// ========== 执行示例 ==========

console.log('🎯 Reclaim Attestor 前端调用示例');
console.log('📚 用途: 演示前端如何直接调用 attestor 获取 claim');
console.log('⚠️  注意: 请确保已通过后端 API 创建了相应的任务\n');

getClaimFromAttestor()
  .then(result => {
    if (result.success) {
      console.log('\n🎉 示例执行成功!');
      console.log('💡 现在您可以将获得的 claim 用于后续的验证或上链操作');
      process.exit(0);
    } else {
      console.log('\n💥 示例执行失败:', result.error);
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('\n💥 未捕获的错误:', error);
    process.exit(1);
  }); 