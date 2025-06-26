const fs = require('fs');
const path = require('path');

// 数据文件路径
const DATA_DIR = path.join(__dirname, 'data');
const INPUT_PARAMS_FILE = path.join(DATA_DIR, 'verify-proofs-input-params.json');
const RPC_REQUESTS_FILE = path.join(DATA_DIR, 'verify-proofs-rpc-requests.json');
const VERIFICATION_RESULTS_FILE = path.join(DATA_DIR, 'verify-proofs-results.json');

// 查看最新的验证结果（从三个文件中获取）
function viewLatestVerification() {
  console.log('📁 查看最新的验证结果\n');

  // 读取三个文件的最新记录
  const inputParams = getLatestRecord(INPUT_PARAMS_FILE, '入参');
  const rpcRequest = getLatestRecord(RPC_REQUESTS_FILE, 'RPC请求');
  const verificationResult = getLatestRecord(VERIFICATION_RESULTS_FILE, '验证结果');

  if (!inputParams && !rpcRequest && !verificationResult) {
    console.log('❌ 未找到任何验证数据');
    console.log('💡 请先运行 verify-proofs.js 来进行验证');
    return;
  }

  console.log('='.repeat(60));
  console.log('📋 最新验证结果');
  console.log('='.repeat(60));

  // 显示基本信息
  const taskId = inputParams?.taskId || rpcRequest?.taskId || verificationResult?.taskId;
  console.log(`任务ID: ${taskId}`);

  if (verificationResult) {
    console.log(`验证时间: ${new Date(verificationResult.timestamp).toLocaleString()}`);
    console.log(`验证状态: ${verificationResult.success ? '✅ 成功' : '❌ 失败'}`);

    if (verificationResult.success) {
      console.log(`共识状态: ${verificationResult.consensusReached ? '✅ 已达成' : '❌ 未达成'}`);
      console.log(`交易哈希: ${verificationResult.transactionHash}`);
      console.log(`Gas使用量: ${verificationResult.gasUsed}`);
      console.log(`区块号: ${verificationResult.blockNumber}`);
    } else {
      console.log(`错误信息: ${verificationResult.error}`);
    }
  }

  if (inputParams) {
    console.log(`验证费用: ${inputParams.verificationCost ? (parseInt(inputParams.verificationCost) / 1e18).toFixed(6) : 'N/A'} ETH`);
    console.log(`Proofs数量: ${inputParams.proofsCount}`);
  }
  console.log('');

  // 显示RPC请求详情
  if (rpcRequest) {
    console.log('🔧 RPC请求详情:');
    console.log(`   方法: ${rpcRequest.method}`);
    console.log(`   合约地址: ${rpcRequest.contractAddress}`);
    console.log(`   网络: ${rpcRequest.network}`);
    console.log(`   任务ID: ${rpcRequest.params.taskId}`);
    console.log(`   Proofs数量: ${rpcRequest.params.proofs.length}`);
    if (rpcRequest.params.value) {
      console.log(`   支付金额: ${(parseInt(rpcRequest.params.value) / 1e18).toFixed(6)} ETH`);
    }
    if (rpcRequest.gasEstimate) {
      console.log(`   Gas估算: ${rpcRequest.gasEstimate}`);
    }
    console.log('');
  }

  // 显示输入的Proofs详情
  if (inputParams && inputParams.proofs) {
    console.log('👥 输入的Proofs详情:');
    inputParams.proofs.forEach((proof, index) => {
      console.log(`🔸 Proof ${index + 1}:`);
      console.log(`   Provider: ${proof.claimInfo.provider}`);
      console.log(`   Owner: ${proof.signedClaim.claim.owner}`);
      console.log(`   Timestamp: ${new Date(proof.signedClaim.claim.timestampS * 1000).toLocaleString()}`);
      console.log(`   Epoch: ${proof.signedClaim.claim.epoch}`);
      console.log(`   Identifier: ${proof.signedClaim.claim.identifier.substring(0, 20)}...`);
      console.log(`   Signatures: ${proof.signedClaim.signatures.length}`);
      console.log('');
    });
  }

  console.log('='.repeat(60));
}

// 辅助函数：获取文件的最新记录
function getLatestRecord(filePath, fileType) {
  if (!fs.existsSync(filePath)) {
    console.log(`⚠️  未找到${fileType}文件: ${path.basename(filePath)}`);
    return null;
  }

  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (Array.isArray(data) && data.length > 0) {
      return data[data.length - 1]; // 返回最新的记录
    }
    return null;
  } catch (error) {
    console.error(`❌ 读取${fileType}文件失败:`, error.message);
    return null;
  }
}

// 查看验证入参历史
function viewInputParamsHistory() {
  console.log('📋 查看验证入参历史\n');

  if (!fs.existsSync(INPUT_PARAMS_FILE)) {
    console.log('❌ 未找到入参历史文件');
    console.log('💡 请先运行 verify-proofs.js 来进行验证');
    return;
  }

  try {
    const history = JSON.parse(fs.readFileSync(INPUT_PARAMS_FILE, 'utf8'));

    if (history.length === 0) {
      console.log('❌ 暂无入参历史记录');
      return;
    }

    console.log('='.repeat(60));
    console.log(`📋 验证入参历史 (共 ${history.length} 次)`);
    console.log('='.repeat(60));

    history.forEach((record, index) => {
      console.log(`📋 入参 ${index + 1}:`);
      console.log(`   任务ID: ${record.taskId}`);
      console.log(`   时间: ${new Date(record.timestamp).toLocaleString()}`);
      console.log(`   验证费用: ${record.verificationCost ? (parseInt(record.verificationCost) / 1e18).toFixed(6) : 'N/A'} ETH`);
      console.log(`   Proofs数量: ${record.proofsCount}`);
      console.log('');
    });

    console.log('='.repeat(60));

  } catch (error) {
    console.error('❌ 读取入参文件失败:', error.message);
  }
}

// 查看RPC请求历史
function viewRpcRequestsHistory() {
  console.log('🔧 查看RPC请求历史\n');

  if (!fs.existsSync(RPC_REQUESTS_FILE)) {
    console.log('❌ 未找到RPC请求历史文件');
    console.log('💡 请先运行 verify-proofs.js 来进行验证');
    return;
  }

  try {
    const history = JSON.parse(fs.readFileSync(RPC_REQUESTS_FILE, 'utf8'));

    if (history.length === 0) {
      console.log('❌ 暂无RPC请求历史记录');
      return;
    }

    console.log('='.repeat(60));
    console.log(`🔧 RPC请求历史 (共 ${history.length} 次)`);
    console.log('='.repeat(60));

    history.forEach((record, index) => {
      console.log(`🔧 请求 ${index + 1}:`);
      console.log(`   任务ID: ${record.taskId}`);
      console.log(`   时间: ${new Date(record.timestamp).toLocaleString()}`);
      console.log(`   方法: ${record.method}`);
      console.log(`   合约: ${record.contractAddress}`);
      console.log(`   网络: ${record.network}`);
      console.log(`   Proofs数量: ${record.params.proofs.length}`);
      if (record.params.value) {
        console.log(`   支付金额: ${(parseInt(record.params.value) / 1e18).toFixed(6)} ETH`);
      }
      if (record.gasEstimate) {
        console.log(`   Gas估算: ${record.gasEstimate}`);
      }
      console.log('');
    });

    console.log('='.repeat(60));

  } catch (error) {
    console.error('❌ 读取RPC请求文件失败:', error.message);
  }
}

// 查看验证结果历史
function viewVerificationHistory() {
  console.log('📊 查看验证结果历史\n');

  if (!fs.existsSync(VERIFICATION_RESULTS_FILE)) {
    console.log('❌ 未找到验证结果历史文件');
    console.log('💡 请先运行 verify-proofs.js 来进行验证');
    return;
  }

  try {
    const history = JSON.parse(fs.readFileSync(VERIFICATION_RESULTS_FILE, 'utf8'));

    if (history.length === 0) {
      console.log('❌ 暂无验证结果历史记录');
      return;
    }

    console.log('='.repeat(60));
    console.log(`📊 验证结果历史 (共 ${history.length} 次)`);
    console.log('='.repeat(60));

    history.forEach((record, index) => {
      console.log(`📊 结果 ${index + 1}:`);
      console.log(`   任务ID: ${record.taskId}`);
      console.log(`   时间: ${new Date(record.timestamp).toLocaleString()}`);
      console.log(`   状态: ${record.success ? '✅ 成功' : '❌ 失败'}`);

      if (record.success) {
        console.log(`   共识: ${record.consensusReached ? '✅ 达成' : '❌ 未达成'}`);
        console.log(`   交易: ${record.transactionHash.substring(0, 20)}...`);
        console.log(`   Gas使用: ${record.gasUsed}`);
        console.log(`   区块号: ${record.blockNumber}`);
      } else {
        console.log(`   错误: ${record.error}`);
      }
      console.log('');
    });

    console.log('='.repeat(60));

  } catch (error) {
    console.error('❌ 读取验证结果文件失败:', error.message);
  }
}

// 查看特定验证的详细信息
function viewDetailedVerification(recordIndex) {
  console.log(`📋 查看详细验证信息 (记录 ${recordIndex + 1})\n`);
  
  if (!fs.existsSync(VERIFICATION_RESULTS_FILE)) {
    console.log('❌ 未找到验证历史文件');
    return;
  }
  
  try {
    const history = JSON.parse(fs.readFileSync(VERIFICATION_RESULTS_FILE, 'utf8'));
    
    if (recordIndex >= history.length || recordIndex < 0) {
      console.log(`❌ 无效的记录索引: ${recordIndex + 1}`);
      console.log(`可用记录范围: 1-${history.length}`);
      return;
    }
    
    const record = history[recordIndex];
    
    console.log('='.repeat(60));
    console.log(`📋 详细验证信息 - 记录 ${recordIndex + 1}`);
    console.log('='.repeat(60));
    console.log(`任务ID: ${record.taskId}`);
    console.log(`时间: ${new Date(record.timestamp).toLocaleString()}`);
    console.log(`状态: ${record.success ? '✅ 成功' : '❌ 失败'}`);
    console.log('');
    
    if (record.success) {
      console.log('✅ 验证成功详情:');
      console.log(`   共识状态: ${record.consensusReached ? '✅ 已达成' : '❌ 未达成'}`);
      console.log(`   交易哈希: ${record.transactionHash}`);
      if (record.verificationCost) {
        console.log(`   验证费用: ${(parseInt(record.verificationCost) / 1e18).toFixed(6)} ETH`);
      }
      console.log('');
    } else {
      console.log('❌ 验证失败详情:');
      console.log(`   错误信息: ${record.error}`);
      console.log('');
    }
    
    // 显示完整的RPC请求
    console.log('🔧 完整RPC请求:');
    console.log(`   方法: ${record.rpcRequest.method}`);
    console.log(`   参数:`);
    console.log(`     任务ID: ${record.rpcRequest.params.taskId}`);
    console.log(`     Proofs数量: ${record.rpcRequest.params.proofs.length}`);
    if (record.rpcRequest.params.value) {
      console.log(`     支付金额: ${record.rpcRequest.params.value} wei`);
    }
    console.log('');
    
    // 显示所有Proofs的详细信息
    console.log('👥 所有Proofs详细信息:');
    record.inputData.proofs.forEach((proof, index) => {
      console.log(`\n🔸 Proof ${index + 1}:`);
      console.log(`   ClaimInfo:`);
      console.log(`     Provider: ${proof.claimInfo.provider}`);
      console.log(`     Parameters: ${proof.claimInfo.parameters.substring(0, 100)}...`);
      console.log(`     Context: ${proof.claimInfo.context || '(empty)'}`);
      
      console.log(`   SignedClaim:`);
      console.log(`     Identifier: ${proof.signedClaim.claim.identifier}`);
      console.log(`     Owner: ${proof.signedClaim.claim.owner}`);
      console.log(`     Timestamp: ${proof.signedClaim.claim.timestampS} (${new Date(proof.signedClaim.claim.timestampS * 1000).toLocaleString()})`);
      console.log(`     Epoch: ${proof.signedClaim.claim.epoch}`);
      console.log(`     Signatures (${proof.signedClaim.signatures.length}):`);
      
      proof.signedClaim.signatures.forEach((sig, sigIndex) => {
        console.log(`       ${sigIndex + 1}: ${sig.substring(0, 20)}...`);
      });
    });
    
    console.log('\n' + '='.repeat(60));
    
  } catch (error) {
    console.error('❌ 读取详细信息失败:', error.message);
  }
}

// 导出验证数据用于分析
function exportVerificationData() {
  console.log('📤 导出验证数据用于分析\n');
  
  if (!fs.existsSync(LATEST_VERIFICATION_FILE)) {
    console.log('❌ 未找到最新的验证文件');
    return null;
  }
  
  try {
    const data = JSON.parse(fs.readFileSync(LATEST_VERIFICATION_FILE, 'utf8'));
    
    const exportData = {
      taskId: data.taskId,
      timestamp: data.timestamp,
      success: data.success,
      consensusReached: data.consensusReached,
      transactionHash: data.transactionHash,
      verificationCost: data.verificationCost,
      proofsCount: data.inputData.proofsCount,
      // 简化的proof数据用于分析
      proofsAnalysis: data.inputData.proofs.map(proof => ({
        provider: proof.claimInfo.provider,
        owner: proof.signedClaim.claim.owner,
        timestampS: proof.signedClaim.claim.timestampS,
        epoch: proof.signedClaim.claim.epoch,
        signaturesCount: proof.signedClaim.signatures.length
      }))
    };
    
    const exportFile = path.join(DATA_DIR, 'verification-analysis.json');
    fs.writeFileSync(exportFile, JSON.stringify(exportData, null, 2));
    
    console.log(`✅ 验证数据已导出到: ${exportFile}`);
    console.log('💡 这个文件包含了简化的验证数据，便于分析');
    
    return exportData;
    
  } catch (error) {
    console.error('❌ 导出验证数据失败:', error.message);
    return null;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    viewLatestVerification();
  } else if (args[0] === 'input') {
    viewInputParamsHistory();
  } else if (args[0] === 'rpc') {
    viewRpcRequestsHistory();
  } else if (args[0] === 'results') {
    viewVerificationHistory();
  } else if (args[0] === 'detail' && args[1]) {
    const index = parseInt(args[1]) - 1; // 用户输入从1开始，数组从0开始
    viewDetailedVerification(index);
  } else if (args[0] === 'export') {
    exportVerificationData();
  } else {
    console.log('用法:');
    console.log('  node view-verification-results.js           # 查看最新验证结果（综合）');
    console.log('  node view-verification-results.js input     # 查看验证入参历史');
    console.log('  node view-verification-results.js rpc       # 查看RPC请求历史');
    console.log('  node view-verification-results.js results   # 查看验证结果历史');
    console.log('  node view-verification-results.js detail <n> # 查看第n个记录的详细信息');
    console.log('  node view-verification-results.js export    # 导出数据用于分析');
  }
}

module.exports = {
  viewLatestVerification,
  viewInputParamsHistory,
  viewRpcRequestsHistory,
  viewVerificationHistory,
  viewDetailedVerification,
  exportVerificationData,
  getLatestRecord
};
