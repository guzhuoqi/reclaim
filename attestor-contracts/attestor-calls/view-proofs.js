const fs = require('fs');
const path = require('path');

// 数据文件路径
const DATA_DIR = path.join(__dirname, 'data');
const PROOFS_FILE = path.join(DATA_DIR, 'attestor-proofs.json');
const LATEST_PROOFS_FILE = path.join(DATA_DIR, 'latest-proofs.json');

// 查看最新的proof结果
function viewLatestProofs() {
  console.log('📁 查看最新的Proof结果\n');
  
  if (!fs.existsSync(LATEST_PROOFS_FILE)) {
    console.log('❌ 未找到最新的proof文件');
    console.log('💡 请先运行 call-attestors.js 来生成proof数据');
    return;
  }
  
  try {
    const data = JSON.parse(fs.readFileSync(LATEST_PROOFS_FILE, 'utf8'));
    
    console.log('='.repeat(60));
    console.log('📋 最新Proof结果');
    console.log('='.repeat(60));
    console.log(`任务ID: ${data.taskId}`);
    console.log(`生成时间: ${new Date(data.timestamp).toLocaleString()}`);
    console.log(`总Attestors数量: ${data.totalAttestors}`);
    console.log(`成功调用: ${data.successfulCalls}`);
    console.log(`失败调用: ${data.failedCalls}`);
    console.log('');
    
    // 显示Binance数据
    if (data.binanceData) {
      console.log('💰 Binance API数据:');
      console.log(`   Symbol: ${data.binanceData.symbol}`);
      console.log(`   Price: $${data.binanceData.price}`);
      console.log('');
    }
    
    // 显示ProviderParams
    console.log('🔧 ProviderParams:');
    console.log(`   方法: ${data.providerParams.method}`);
    console.log(`   URL: ${data.providerParams.url}`);
    console.log(`   响应匹配模式: ${data.providerParams.responseMatches[0].value}`);
    console.log('');
    
    // 显示每个attestor的结果
    console.log('👥 Attestor调用结果:');
    data.results.forEach((result, index) => {
      console.log(`🔸 Attestor ${index + 1}:`);
      console.log(`   地址: ${result.attestorAddress}`);
      console.log(`   Host: ${result.attestorHost}`);
      console.log(`   状态: ${result.success ? '✅ 成功' : '❌ 失败'}`);
      
      if (result.success) {
        console.log(`   Proof生成: ✅ 完成`);
        if (result.proof) {
          console.log(`   Proof标识符: ${result.proof.identifier || 'N/A'}`);
          console.log(`   签名数量: ${result.proof.signatures ? result.proof.signatures.length : 0}`);
        }
      } else {
        console.log(`   错误信息: ${result.error}`);
      }
      console.log(`   时间戳: ${new Date(result.timestamp).toLocaleString()}`);
      console.log('');
    });
    
    console.log('='.repeat(60));
    
  } catch (error) {
    console.error('❌ 读取proof文件失败:', error.message);
  }
}

// 查看proof历史记录
function viewProofHistory() {
  console.log('📚 查看Proof历史记录\n');
  
  if (!fs.existsSync(PROOFS_FILE)) {
    console.log('❌ 未找到proof历史文件');
    console.log('💡 请先运行 call-attestors.js 来生成proof数据');
    return;
  }
  
  try {
    const history = JSON.parse(fs.readFileSync(PROOFS_FILE, 'utf8'));
    
    if (history.length === 0) {
      console.log('❌ 暂无proof历史记录');
      return;
    }
    
    console.log('='.repeat(60));
    console.log(`📚 Proof历史记录 (共 ${history.length} 次调用)`);
    console.log('='.repeat(60));
    
    history.forEach((record, index) => {
      console.log(`📋 记录 ${index + 1}:`);
      console.log(`   任务ID: ${record.taskId}`);
      console.log(`   时间: ${new Date(record.timestamp).toLocaleString()}`);
      console.log(`   成功/总数: ${record.successfulCalls}/${record.totalAttestors}`);
      if (record.binanceData) {
        console.log(`   ETH价格: $${record.binanceData.price}`);
      }
      console.log('');
    });
    
    console.log('='.repeat(60));
    
  } catch (error) {
    console.error('❌ 读取历史文件失败:', error.message);
  }
}

// 查看特定记录的详细信息
function viewDetailedProof(recordIndex) {
  console.log(`📋 查看详细Proof信息 (记录 ${recordIndex + 1})\n`);
  
  if (!fs.existsSync(PROOFS_FILE)) {
    console.log('❌ 未找到proof历史文件');
    return;
  }
  
  try {
    const history = JSON.parse(fs.readFileSync(PROOFS_FILE, 'utf8'));
    
    if (recordIndex >= history.length || recordIndex < 0) {
      console.log(`❌ 无效的记录索引: ${recordIndex + 1}`);
      console.log(`可用记录范围: 1-${history.length}`);
      return;
    }
    
    const record = history[recordIndex];
    
    console.log('='.repeat(60));
    console.log(`📋 详细Proof信息 - 记录 ${recordIndex + 1}`);
    console.log('='.repeat(60));
    console.log(`任务ID: ${record.taskId}`);
    console.log(`时间: ${new Date(record.timestamp).toLocaleString()}`);
    console.log('');
    
    // 显示成功的proofs
    const successfulResults = record.results.filter(r => r.success);
    if (successfulResults.length > 0) {
      console.log('✅ 成功生成的Proofs:');
      successfulResults.forEach((result, index) => {
        console.log(`\n🔸 Proof ${index + 1}:`);
        console.log(`   Attestor: ${result.attestorHost}`);
        console.log(`   地址: ${result.attestorAddress}`);
        
        if (result.proof) {
          console.log(`   Proof详情:`);
          console.log(`     标识符: ${result.proof.identifier || 'N/A'}`);
          console.log(`     签名数量: ${result.proof.signatures ? result.proof.signatures.length : 0}`);
          
          if (result.proof.claimData) {
            console.log(`     Claim数据:`);
            console.log(`       Provider: ${result.proof.claimData.provider || 'N/A'}`);
            console.log(`       Owner: ${result.proof.claimData.owner || 'N/A'}`);
            console.log(`       时间戳: ${result.proof.claimData.timestampS || 'N/A'}`);
          }
          
          if (result.proof.signatures && result.proof.signatures.length > 0) {
            console.log(`     签名: ${result.proof.signatures[0].substring(0, 20)}...`);
          }
        }
      });
    }
    
    // 显示失败的调用
    const failedResults = record.results.filter(r => !r.success);
    if (failedResults.length > 0) {
      console.log('\n❌ 失败的调用:');
      failedResults.forEach((result, index) => {
        console.log(`\n🔸 失败 ${index + 1}:`);
        console.log(`   Attestor: ${result.attestorHost}`);
        console.log(`   错误: ${result.error}`);
      });
    }
    
    console.log('\n' + '='.repeat(60));
    
  } catch (error) {
    console.error('❌ 读取详细信息失败:', error.message);
  }
}

// 导出成功的proofs用于合约验证
function exportProofsForVerification() {
  console.log('📤 导出Proofs用于合约验证\n');
  
  if (!fs.existsSync(LATEST_PROOFS_FILE)) {
    console.log('❌ 未找到最新的proof文件');
    return null;
  }
  
  try {
    const data = JSON.parse(fs.readFileSync(LATEST_PROOFS_FILE, 'utf8'));
    const successfulResults = data.results.filter(r => r.success);
    
    if (successfulResults.length === 0) {
      console.log('❌ 没有成功的proof可以导出');
      return null;
    }
    
    const exportData = {
      taskId: data.taskId,
      timestamp: data.timestamp,
      proofs: successfulResults.map(result => ({
        // 使用 attestor 返回的完整 response 数据
        claim: result.response.claim,
        signatures: result.response.signatures,
        attestorAddress: result.attestorAddress,
        attestorHost: result.attestorHost,
        // 添加一些元数据
        metadata: {
          attestorIndex: result.attestorIndex,
          timestamp: result.timestamp
        }
      })),
      metadata: {
        totalAttestors: data.totalAttestors,
        successfulProofs: successfulResults.length,
        binanceData: data.binanceData,
        providerParams: data.providerParams
      }
    };
    
    const exportFile = path.join(DATA_DIR, 'proofs-for-verification.json');
    fs.writeFileSync(exportFile, JSON.stringify(exportData, null, 2));
    
    console.log(`✅ 已导出 ${successfulResults.length} 个proof到: ${exportFile}`);
    console.log('💡 这个文件可以用于下一步的合约验证');
    
    return exportData;
    
  } catch (error) {
    console.error('❌ 导出proof失败:', error.message);
    return null;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    viewLatestProofs();
  } else if (args[0] === 'history') {
    viewProofHistory();
  } else if (args[0] === 'detail' && args[1]) {
    const index = parseInt(args[1]) - 1; // 用户输入从1开始，数组从0开始
    viewDetailedProof(index);
  } else if (args[0] === 'export') {
    exportProofsForVerification();
  } else {
    console.log('用法:');
    console.log('  node view-proofs.js           # 查看最新proof结果');
    console.log('  node view-proofs.js history   # 查看历史记录');
    console.log('  node view-proofs.js detail <n> # 查看第n个记录的详细信息');
    console.log('  node view-proofs.js export    # 导出proofs用于验证');
  }
}

module.exports = {
  viewLatestProofs,
  viewProofHistory,
  viewDetailedProof,
  exportProofsForVerification
};
