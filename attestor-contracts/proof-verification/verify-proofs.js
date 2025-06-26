const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

// 配置信息
const CONFIG = {
  reclaimTaskAddress: '0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820',
  governanceAddress: '0x0d113bDe369DC8Df8e24760473bB3C4965a17078',
  networkURL: 'https://testnet-rpc.mechain.tech',
  privateKey: 'd716026fb6fce2b47a911ef44d36d7e07fd6b09037c0b3d7121f20061388cba6'
};

// ReclaimTask合约ABI (包含verifyProofs方法)
const RECLAIM_TASK_ABI = [
  "function verifyProofs(tuple(tuple(string provider, string parameters, string context) claimInfo, tuple(tuple(bytes32 identifier, address owner, uint32 timestampS, uint32 epoch) claim, bytes[] signatures) signedClaim)[] proofs, uint32 taskId) public payable returns (bool)",
  "function consensusReached(uint32) public view returns (bool)",
  "function fetchTask(uint32 taskId) public view returns (tuple(uint32 id, uint32 timestampStart, uint32 timestampEnd, tuple(address addr, string host)[] attestors))",
  "function currentTask() public view returns (uint32)"
];

// Governance合约ABI (获取验证费用)
const GOVERNANCE_ABI = [
  "function verificationCost() public view returns (uint256)"
];

// 数据目录
const DATA_DIR = path.join(__dirname, 'data');
const INPUT_PARAMS_FILE = path.join(DATA_DIR, 'verify-proofs-input-params.json');
const RPC_REQUESTS_FILE = path.join(DATA_DIR, 'verify-proofs-rpc-requests.json');
const VERIFICATION_RESULTS_FILE = path.join(DATA_DIR, 'verify-proofs-results.json');

// 确保数据目录存在
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// 读取attestor生成的proofs
function getAttestorProofs() {
  const proofsPath = path.join(__dirname, '../attestor-calls/data/proofs-for-verification.json');
  
  if (!fs.existsSync(proofsPath)) {
    throw new Error('未找到attestor proofs文件，请先运行attestor调用脚本');
  }
  
  try {
    const proofsData = JSON.parse(fs.readFileSync(proofsPath, 'utf8'));
    return proofsData;
  } catch (error) {
    throw new Error('读取attestor proofs失败: ' + error.message);
  }
}

// 将attestor返回的数据转换为合约需要的Proof结构
function convertToContractProofs(attestorProofs) {
  console.log('🔄 正在转换Proof数据格式...');
  
  const contractProofs = [];
  
  for (let i = 0; i < attestorProofs.proofs.length; i++) {
    const attestorProof = attestorProofs.proofs[i];
    
    console.log(`📋 处理Proof ${i + 1}:`);
    console.log(`   Attestor: ${attestorProof.attestorHost}`);
    console.log(`   Claim ID: ${attestorProof.claim.identifier.substring(0, 20)}...`);
    
    // 构建ClaimInfo结构
    const claimInfo = {
      provider: attestorProof.claim.provider,
      parameters: attestorProof.claim.parameters,
      context: attestorProof.claim.context || ''
    };
    
    // 构建SignedClaim结构
    const signedClaim = {
      claim: {
        identifier: attestorProof.claim.identifier,
        owner: attestorProof.claim.owner,
        timestampS: attestorProof.claim.timestampS,
        epoch: attestorProof.claim.epoch
      },
      signatures: [
        // 确保签名是十六进制字符串格式
        typeof attestorProof.signatures.claimSignature === 'string'
          ? attestorProof.signatures.claimSignature
          : '0x' + Buffer.from(attestorProof.signatures.claimSignature.data || attestorProof.signatures.claimSignature).toString('hex')
      ].filter(sig => sig && sig !== '0x') // 只使用claimSignature
    };
    
    // 构建完整的Proof结构
    const contractProof = {
      claimInfo: claimInfo,
      signedClaim: signedClaim
    };
    
    contractProofs.push(contractProof);
    console.log(`   ✅ Proof ${i + 1} 转换完成`);
  }
  
  console.log(`✅ 总共转换了 ${contractProofs.length} 个Proofs\n`);
  return contractProofs;
}

// 获取验证费用
async function getVerificationCost(provider) {
  try {
    console.log('💰 正在获取验证费用...');
    
    const governanceContract = new ethers.Contract(
      CONFIG.governanceAddress,
      GOVERNANCE_ABI,
      provider
    );
    
    const cost = await governanceContract.verificationCost();
    console.log(`✅ 验证费用: ${ethers.formatEther(cost)} ETH\n`);
    
    return cost;
  } catch (error) {
    console.error('❌ 获取验证费用失败:', error.message);
    throw error;
  }
}

// 保存验证入参
function saveInputParams(taskId, contractProofs, verificationCost) {
  ensureDataDir();

  const inputData = {
    taskId: taskId.toString(),
    timestamp: new Date().toISOString(),
    verificationCost: verificationCost ? verificationCost.toString() : null,
    proofsCount: contractProofs.length,
    proofs: contractProofs
  };

  // 添加到入参历史记录
  let inputHistory = [];
  if (fs.existsSync(INPUT_PARAMS_FILE)) {
    try {
      inputHistory = JSON.parse(fs.readFileSync(INPUT_PARAMS_FILE, 'utf8'));
    } catch (e) {
      inputHistory = [];
    }
  }

  inputHistory.push(inputData);
  fs.writeFileSync(INPUT_PARAMS_FILE, JSON.stringify(inputHistory, null, 2));

  return inputData;
}

// 保存RPC请求
function saveRpcRequest(taskId, contractProofs, verificationCost, gasEstimate = null) {
  ensureDataDir();

  const rpcData = {
    taskId: taskId.toString(),
    timestamp: new Date().toISOString(),
    method: 'verifyProofs',
    contractAddress: CONFIG.reclaimTaskAddress,
    params: {
      proofs: contractProofs,
      taskId: taskId,
      value: verificationCost ? verificationCost.toString() : null
    },
    gasEstimate: gasEstimate ? gasEstimate.toString() : null,
    network: CONFIG.networkURL
  };

  // 添加到RPC请求历史记录
  let rpcHistory = [];
  if (fs.existsSync(RPC_REQUESTS_FILE)) {
    try {
      rpcHistory = JSON.parse(fs.readFileSync(RPC_REQUESTS_FILE, 'utf8'));
    } catch (e) {
      rpcHistory = [];
    }
  }

  rpcHistory.push(rpcData);
  fs.writeFileSync(RPC_REQUESTS_FILE, JSON.stringify(rpcHistory, null, 2));

  return rpcData;
}

// 保存链上验证结果
function saveVerificationResult(taskId, txHash, consensusReached, gasUsed, blockNumber, error = null) {
  ensureDataDir();

  const resultData = {
    taskId: taskId.toString(),
    timestamp: new Date().toISOString(),
    success: !error,
    transactionHash: txHash,
    consensusReached: consensusReached,
    gasUsed: gasUsed ? gasUsed.toString() : null,
    blockNumber: blockNumber,
    error: error
  };

  // 添加到验证结果历史记录
  let resultHistory = [];
  if (fs.existsSync(VERIFICATION_RESULTS_FILE)) {
    try {
      resultHistory = JSON.parse(fs.readFileSync(VERIFICATION_RESULTS_FILE, 'utf8'));
    } catch (e) {
      resultHistory = [];
    }
  }

  resultHistory.push(resultData);
  fs.writeFileSync(VERIFICATION_RESULTS_FILE, JSON.stringify(resultHistory, null, 2));

  return resultData;
}

// 主函数：验证proofs
async function verifyProofs(taskId = null) {
  try {
    console.log('🚀 开始验证Proofs...\n');
    
    // 创建provider和wallet
    const provider = new ethers.JsonRpcProvider(CONFIG.networkURL);
    const wallet = new ethers.Wallet(CONFIG.privateKey, provider);
    
    // 连接到合约
    const contract = new ethers.Contract(CONFIG.reclaimTaskAddress, RECLAIM_TASK_ABI, wallet);
    
    console.log(`📋 ReclaimTask 合约地址: ${CONFIG.reclaimTaskAddress}`);
    console.log(`🌐 网络: ${CONFIG.networkURL}`);
    console.log(`👤 发送地址: ${wallet.address}\n`);
    
    // 读取attestor生成的proofs
    console.log('📁 正在读取Attestor生成的Proofs...');
    const attestorProofs = getAttestorProofs();
    
    console.log(`✅ 读取成功! 任务ID: ${attestorProofs.taskId}`);
    console.log(`📊 找到 ${attestorProofs.proofs.length} 个Proofs\n`);
    
    // 确定要验证的任务ID
    const targetTaskId = taskId || parseInt(attestorProofs.taskId);
    console.log(`🎯 目标任务ID: ${targetTaskId}\n`);
    
    // 检查任务是否已经被验证
    console.log('🔍 检查任务状态...');
    const alreadyProcessed = await contract.consensusReached(targetTaskId);
    if (alreadyProcessed) {
      throw new Error(`任务 ${targetTaskId} 已经被验证过了`);
    }
    console.log('✅ 任务尚未被验证，可以继续\n');
    
    // 转换proof格式
    const contractProofs = convertToContractProofs(attestorProofs);
    
    // 获取验证费用
    const verificationCost = await getVerificationCost(provider);
    
    // 显示即将发送的数据
    console.log('📋 验证参数:');
    console.log(`   任务ID: ${targetTaskId}`);
    console.log(`   Proofs数量: ${contractProofs.length}`);
    console.log(`   验证费用: ${ethers.formatEther(verificationCost)} ETH`);
    console.log('');
    
    // 显示每个proof的详细信息
    console.log('👥 Proofs详情:');
    contractProofs.forEach((proof, index) => {
      console.log(`🔸 Proof ${index + 1}:`);
      console.log(`   Provider: ${proof.claimInfo.provider}`);
      console.log(`   Owner: ${proof.signedClaim.claim.owner}`);
      console.log(`   Identifier: ${proof.signedClaim.claim.identifier.substring(0, 20)}...`);
      console.log(`   Signatures: ${proof.signedClaim.signatures.length}`);
      console.log('');
    });
    
    // 保存验证入参
    console.log('💾 正在保存验证入参...');
    const inputData = saveInputParams(targetTaskId, contractProofs, verificationCost);
    console.log(`✅ 入参已保存到: ${INPUT_PARAMS_FILE}\n`);

    // 估算gas费用
    console.log('⛽ 正在估算gas费用...');
    let gasEstimate = null;
    try {
      gasEstimate = await contract.verifyProofs.estimateGas(contractProofs, targetTaskId, {
        value: verificationCost
      });
      console.log(`预估gas: ${gasEstimate.toString()}`);
    } catch (e) {
      console.log('⚠️  无法估算gas费用，继续执行...');
    }

    // 保存RPC请求
    console.log('💾 正在保存RPC请求...');
    const rpcData = saveRpcRequest(targetTaskId, contractProofs, verificationCost, gasEstimate);
    console.log(`✅ RPC请求已保存到: ${RPC_REQUESTS_FILE}`);
    console.log('');
    
    // 调用verifyProofs方法
    console.log('='.repeat(60));
    console.log('🔐 正在调用 verifyProofs 方法...');
    console.log('='.repeat(60));
    
    const tx = await contract.verifyProofs(contractProofs, targetTaskId, {
      value: verificationCost
    });
    
    console.log(`📝 交易哈希: ${tx.hash}`);
    console.log('⏳ 等待交易确认...');
    
    const receipt = await tx.wait();
    console.log(`✅ 交易已确认! Gas使用量: ${receipt.gasUsed.toString()}\n`);

    // 检查验证结果
    console.log('🔍 检查验证结果...');
    const consensusReached = await contract.consensusReached(targetTaskId);

    console.log('='.repeat(60));
    console.log('🎉 验证完成!');
    console.log('='.repeat(60));
    console.log(`任务ID: ${targetTaskId}`);
    console.log(`共识状态: ${consensusReached ? '✅ 已达成' : '❌ 未达成'}`);
    console.log(`交易哈希: ${tx.hash}`);
    console.log(`Gas使用量: ${receipt.gasUsed.toString()}`);
    console.log(`区块号: ${receipt.blockNumber}`);
    console.log(`验证费用: ${ethers.formatEther(verificationCost)} ETH\n`);

    // 保存链上验证结果
    console.log('💾 正在保存链上验证结果...');
    const resultData = saveVerificationResult(
      targetTaskId,
      tx.hash,
      consensusReached,
      receipt.gasUsed,
      receipt.blockNumber
    );

    console.log(`✅ 验证数据已分别保存到:`);
    console.log(`   入参文件: ${INPUT_PARAMS_FILE}`);
    console.log(`   RPC请求: ${RPC_REQUESTS_FILE}`);
    console.log(`   验证结果: ${VERIFICATION_RESULTS_FILE}\n`);
    
    console.log('='.repeat(60));
    console.log('✅ 验证流程完成!');
    console.log('='.repeat(60));

    return resultData;
    
  } catch (error) {
    console.error('❌ 验证Proofs时发生错误:', error.message);
    
    // 保存错误信息
    try {
      const attestorProofs = getAttestorProofs();
      const contractProofs = convertToContractProofs(attestorProofs);
      const targetTaskId = taskId || parseInt(attestorProofs.taskId);

      // 保存入参（如果还没保存的话）
      saveInputParams(targetTaskId, contractProofs, null);

      // 保存失败的验证结果
      saveVerificationResult(
        targetTaskId,
        null,
        false,
        null,
        null,
        error.message
      );
    } catch (saveError) {
      console.error('保存错误信息失败:', saveError.message);
    }
    
    throw error;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const args = process.argv.slice(2);
  const taskId = args[0] ? parseInt(args[0]) : null;
  
  verifyProofs(taskId).catch(console.error);
}

module.exports = {
  verifyProofs,
  getAttestorProofs,
  convertToContractProofs,
  getVerificationCost,
  saveInputParams,
  saveRpcRequest,
  saveVerificationResult
};
