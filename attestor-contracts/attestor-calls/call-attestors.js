const { createClaimOnAttestor } = require('@reclaimprotocol/attestor-core');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

// 配置信息
const CONFIG = {
  privateKey: 'd716026fb6fce2b47a911ef44d36d7e07fd6b09037c0b3d7121f20061388cba6',
  binanceAPI: 'https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT'
};

// 数据目录
const DATA_DIR = path.join(__dirname, 'data');
const PROOFS_FILE = path.join(DATA_DIR, 'attestor-proofs.json');
const LATEST_PROOFS_FILE = path.join(DATA_DIR, 'latest-proofs.json');

// 确保数据目录存在
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// 生成Binance API的ProviderParams
function generateBinanceProviderParams() {
  return {
    method: 'GET',
    url: CONFIG.binanceAPI,
    responseMatches: [
      {
        type: 'regex',
        value: '\\{"symbol":"ETHUSDT","price":"(?<price>[\\d\\.]+)"\\}'
      }
    ],
    responseRedactions: []
  };
}

// 生成SecretParams
function generateSecretParams() {
  return {
    headers: {
      'accept': 'application/json, text/plain, */*',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  };
}

// 测试Binance API连接
async function testBinanceAPI() {
  try {
    console.log('🔍 正在测试Binance API连接...');
    const response = await axios.get(CONFIG.binanceAPI);
    console.log(`✅ API连接成功! 当前ETH价格: $${response.data.price}`);
    return response.data;
  } catch (error) {
    console.error('❌ Binance API连接失败:', error.message);
    throw error;
  }
}

// 读取最新的任务attestors信息
function getLatestTaskAttestors() {
  const taskDataPath = path.join(__dirname, '../task-management/data/latest-attestors.json');
  
  if (!fs.existsSync(taskDataPath)) {
    throw new Error('未找到任务数据文件，请先创建一个任务');
  }
  
  try {
    const taskData = JSON.parse(fs.readFileSync(taskDataPath, 'utf8'));
    return taskData;
  } catch (error) {
    throw new Error('读取任务数据失败: ' + error.message);
  }
}

// 调用单个attestor
async function callSingleAttestor(attestor, providerParams, secretParams, index) {
  try {
    console.log(`🔗 正在连接到 Attestor ${index + 1}: ${attestor.host}`);

    console.log(`📋 正在请求 Attestor ${index + 1} 创建claim...`);

    // 使用 createClaimOnAttestor 函数直接调用 attestor 节点
    const response = await createClaimOnAttestor({
      name: 'http',
      params: providerParams,
      secretParams: secretParams,
      ownerPrivateKey: '0x' + CONFIG.privateKey,
      client: {
        url: attestor.host
      }
    });

    console.log(`✅ Attestor ${index + 1} 响应成功!`);
    console.log(`📋 Attestor ${index + 1} 返回的数据类型:`, typeof response);
    console.log(`📋 Attestor ${index + 1} 返回的数据键:`, Object.keys(response));

    // 检查响应结构
    if (response.claim) {
      console.log(`📋 Claim 数据:`, {
        identifier: response.claim.identifier,
        provider: response.claim.provider,
        owner: response.claim.owner,
        timestampS: response.claim.timestampS
      });
    }

    if (response.signatures) {
      console.log(`📋 签名数据:`, {
        attestorAddress: response.signatures.attestorAddress,
        claimSignature: response.signatures.claimSignature ? 'present' : 'missing',
        resultSignature: response.signatures.resultSignature ? 'present' : 'missing'
      });
    }

    return {
      attestorIndex: index,
      attestorAddress: attestor.address,
      attestorHost: attestor.host,
      success: true,
      response: response,
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error(`❌ Attestor ${index + 1} 调用失败:`, error.message);

    return {
      attestorIndex: index,
      attestorAddress: attestor.address,
      attestorHost: attestor.host,
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

// 保存proof结果到文件
function saveProofResults(taskData, providerParams, results, binanceData) {
  ensureDataDir();

  const proofData = {
    taskId: taskData.taskId,
    timestamp: new Date().toISOString(),
    method: 'attestor-core-rpc',
    providerParams: providerParams,
    binanceData: binanceData,
    totalAttestors: taskData.attestors.length,
    successfulCalls: results.filter(r => r.success).length,
    failedCalls: results.filter(r => !r.success).length,
    results: results
  };

  // 保存最新的proof结果
  fs.writeFileSync(LATEST_PROOFS_FILE, JSON.stringify(proofData, null, 2));

  // 添加到历史记录
  let proofsHistory = [];
  if (fs.existsSync(PROOFS_FILE)) {
    try {
      proofsHistory = JSON.parse(fs.readFileSync(PROOFS_FILE, 'utf8'));
    } catch (e) {
      proofsHistory = [];
    }
  }

  proofsHistory.push(proofData);
  fs.writeFileSync(PROOFS_FILE, JSON.stringify(proofsHistory, null, 2));

  return proofData;
}

// 主函数：调用所有attestors
async function callAllAttestors(taskId = null) {
  try {
    console.log('🚀 开始调用Attestors进行claim创建...\n');

    // 测试Binance API
    const binanceData = await testBinanceAPI();
    console.log('');

    // 生成ProviderParams和SecretParams
    console.log('📋 正在生成ProviderParams...');
    const providerParams = generateBinanceProviderParams();
    const secretParams = generateSecretParams();
    console.log('✅ ProviderParams生成完成\n');

    // 读取任务数据
    console.log('📁 正在读取任务数据...');
    const taskData = getLatestTaskAttestors();

    if (taskId && taskData.taskId !== taskId.toString()) {
      throw new Error(`指定的任务ID ${taskId} 与最新任务ID ${taskData.taskId} 不匹配`);
    }

    console.log(`✅ 任务数据读取成功! 任务ID: ${taskData.taskId}`);
    console.log(`📊 找到 ${taskData.attestors.length} 个Attestors\n`);

    // 显示将要调用的attestors
    console.log('👥 将要调用的Attestors:');
    taskData.attestors.forEach((attestor, index) => {
      console.log(`🔸 Attestor ${index + 1}:`);
      console.log(`   地址: ${attestor.address}`);
      console.log(`   Host: ${attestor.host}`);
      console.log('');
    });

    // 显示ProviderParams信息
    console.log('🔧 ProviderParams配置:');
    console.log(`   方法: ${providerParams.method}`);
    console.log(`   URL: ${providerParams.url}`);
    console.log(`   响应匹配: ${JSON.stringify(providerParams.responseMatches[0])}`);
    console.log('');

    // 开始调用attestors
    console.log('='.repeat(60));
    console.log('🔄 开始调用Attestors...');
    console.log('='.repeat(60));

    const results = [];

    for (let i = 0; i < taskData.attestors.length; i++) {
      const attestor = taskData.attestors[i];
      console.log(`\n📞 调用 Attestor ${i + 1}/${taskData.attestors.length}:`);

      const result = await callSingleAttestor(attestor, providerParams, secretParams, i);
      results.push(result);

      // 添加延迟避免过快调用
      if (i < taskData.attestors.length - 1) {
        console.log('⏳ 等待2秒后继续下一个attestor...');
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    // 显示结果摘要
    console.log('\n' + '='.repeat(60));
    console.log('📊 调用结果摘要');
    console.log('='.repeat(60));

    const successCount = results.filter(r => r.success).length;
    const failCount = results.filter(r => !r.success).length;

    console.log(`✅ 成功调用: ${successCount}/${taskData.attestors.length}`);
    console.log(`❌ 失败调用: ${failCount}/${taskData.attestors.length}`);
    console.log('');

    // 显示详细结果
    results.forEach((result, index) => {
      console.log(`🔸 Attestor ${index + 1} (${result.attestorHost}):`);
      if (result.success) {
        console.log(`   状态: ✅ 成功`);
        console.log(`   Proof生成: ✅ 完成`);
        if (result.response && result.response.claim) {
          console.log(`   Claim ID: ${result.response.claim.identifier.substring(0, 20)}...`);
        }
      } else {
        console.log(`   状态: ❌ 失败`);
        console.log(`   错误: ${result.error}`);
      }
      console.log('');
    });

    // 保存结果到文件
    console.log('💾 正在保存结果到文件...');
    const savedData = saveProofResults(taskData, providerParams, results, binanceData);

    console.log(`✅ 结果已保存到:`);
    console.log(`   最新结果: ${LATEST_PROOFS_FILE}`);
    console.log(`   历史记录: ${PROOFS_FILE}`);
    console.log('');

    console.log('='.repeat(60));
    console.log('🎉 Attestor调用完成!');
    console.log('='.repeat(60));

    return savedData;

  } catch (error) {
    console.error('❌ 调用Attestors时发生错误:', error.message);
    throw error;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const args = process.argv.slice(2);
  const taskId = args[0] ? parseInt(args[0]) : null;
  
  callAllAttestors(taskId).catch(console.error);
}

module.exports = {
  callAllAttestors,
  generateBinanceProviderParams,
  generateSecretParams,
  testBinanceAPI,
  getLatestTaskAttestors
};
