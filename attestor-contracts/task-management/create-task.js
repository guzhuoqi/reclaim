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

// ReclaimTask合约ABI (只包含我们需要的方法)
const RECLAIM_TASK_ABI = [
  "function createNewTaskRequest(bytes32 seed, uint32 timestamp) public returns (uint32, tuple(address addr, string host)[] memory)",
  "function currentTask() public view returns (uint32)",
  "function fetchTask(uint32 taskId) public view returns (tuple(uint32 id, uint32 timestampStart, uint32 timestampEnd, tuple(address addr, string host)[] attestors))",
  "function requiredAttestors() public view returns (uint8)",
  "function taskDurationS() public view returns (uint32)"
];

// 数据存储目录
const DATA_DIR = path.join(__dirname, 'data');
const ATTESTORS_FILE = path.join(DATA_DIR, 'latest-attestors.json');
const TASKS_FILE = path.join(DATA_DIR, 'tasks-history.json');

// 确保数据目录存在
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// 保存attestors信息到文件
function saveAttestorsInfo(taskId, attestors, seed, timestamp) {
  ensureDataDir();
  
  const attestorsData = {
    taskId: taskId.toString(),
    timestamp: new Date().toISOString(),
    seed: typeof seed === 'string' ? seed : ethers.hexlify(seed),
    requestTimestamp: timestamp,
    attestors: attestors.map(attestor => ({
      address: attestor.addr,
      host: attestor.host
    }))
  };
  
  // 保存最新的attestors信息
  fs.writeFileSync(ATTESTORS_FILE, JSON.stringify(attestorsData, null, 2));
  
  // 添加到历史记录
  let tasksHistory = [];
  if (fs.existsSync(TASKS_FILE)) {
    try {
      tasksHistory = JSON.parse(fs.readFileSync(TASKS_FILE, 'utf8'));
    } catch (e) {
      tasksHistory = [];
    }
  }
  
  tasksHistory.push(attestorsData);
  fs.writeFileSync(TASKS_FILE, JSON.stringify(tasksHistory, null, 2));
  
  return attestorsData;
}

// 生成随机种子
function generateRandomSeed() {
  return ethers.randomBytes(32);
}

// 获取当前时间戳
function getCurrentTimestamp() {
  return Math.floor(Date.now() / 1000);
}

async function createNewTask(customSeed = null, customTimestamp = null) {
  try {
    console.log('🔗 正在连接到 MeChain 测试网...');
    
    // 创建provider和wallet
    const provider = new ethers.JsonRpcProvider(CONFIG.networkURL);
    const wallet = new ethers.Wallet(CONFIG.privateKey, provider);
    
    // 连接到合约
    const contract = new ethers.Contract(CONFIG.reclaimTaskAddress, RECLAIM_TASK_ABI, wallet);
    
    console.log(`📋 ReclaimTask 合约地址: ${CONFIG.reclaimTaskAddress}`);
    console.log(`🌐 网络: ${CONFIG.networkURL}`);
    console.log(`👤 发送地址: ${wallet.address}\n`);
    
    // 获取合约基本信息
    console.log('📊 正在获取合约基本信息...');
    const currentTaskId = await contract.currentTask();
    const requiredAttestors = await contract.requiredAttestors();
    const taskDuration = await contract.taskDurationS();
    
    console.log(`当前任务ID: ${currentTaskId.toString()}`);
    console.log(`所需attestors数量: ${requiredAttestors.toString()}`);
    console.log(`任务持续时间: ${taskDuration.toString()} 秒 (${Number(taskDuration) / 86400} 天)\n`);
    
    // 准备参数
    const seed = customSeed || generateRandomSeed();
    const timestamp = customTimestamp || getCurrentTimestamp();
    
    console.log('🎲 任务参数:');
    console.log(`Seed: ${typeof seed === 'string' ? seed : ethers.hexlify(seed)}`);
    console.log(`Timestamp: ${timestamp} (${new Date(timestamp * 1000).toLocaleString()})\n`);
    
    // 估算gas费用
    console.log('⛽ 正在估算gas费用...');
    try {
      const gasEstimate = await contract.createNewTaskRequest.estimateGas(seed, timestamp);
        console.log(`预估gas: ${gasEstimate.toString()}`);
    } catch (e) {
      console.log('⚠️  无法估算gas费用，继续执行...');
    }
    
    // 创建新任务
    console.log('🚀 正在创建新任务...');
    const tx = await contract.createNewTaskRequest(seed, timestamp);
    console.log(`📝 交易哈希: ${tx.hash}`);
    
    console.log('⏳ 等待交易确认...');
    const receipt = await tx.wait();
    console.log(`✅ 交易已确认! Gas使用量: ${receipt.gasUsed.toString()}\n`);
    
    // 获取返回值 - 需要解析交易receipt中的事件或重新调用合约
    console.log('📋 正在获取任务详情...');
    const newTaskId = await contract.currentTask();
    const taskDetails = await contract.fetchTask(newTaskId);
    
    console.log('='.repeat(60));
    console.log('🎉 任务创建成功!');
    console.log('='.repeat(60));
    console.log(`新任务ID: ${newTaskId.toString()}`);
    console.log(`任务开始时间: ${new Date(Number(taskDetails.timestampStart) * 1000).toLocaleString()}`);
    console.log(`任务结束时间: ${new Date(Number(taskDetails.timestampEnd) * 1000).toLocaleString()}`);
    console.log(`分配的Attestors数量: ${taskDetails.attestors.length}\n`);
    
    // 显示attestors信息
    console.log('👥 分配的Attestors:');
    taskDetails.attestors.forEach((attestor, index) => {
      console.log(`🔸 Attestor ${index + 1}:`);
      console.log(`   地址: ${attestor.addr}`);
      console.log(`   Host: ${attestor.host}`);
      console.log('');
    });
    
    // 保存attestors信息到文件
    console.log('💾 正在保存attestors信息到本地文件...');
    const savedData = saveAttestorsInfo(newTaskId, taskDetails.attestors, seed, timestamp);
    
    console.log(`✅ Attestors信息已保存到:`);
    console.log(`   最新信息: ${ATTESTORS_FILE}`);
    console.log(`   历史记录: ${TASKS_FILE}\n`);
    
    console.log('='.repeat(60));
    console.log('✅ 任务创建完成!');
    console.log('='.repeat(60));
    
    return {
      taskId: newTaskId,
      attestors: taskDetails.attestors,
      savedData: savedData,
      transactionHash: tx.hash
    };
    
  } catch (error) {
    console.error('❌ 创建任务时发生错误:', error.message);
    if (error.code) {
      console.error(`错误代码: ${error.code}`);
    }
    if (error.reason) {
      console.error(`错误原因: ${error.reason}`);
    }
    throw error;
  }
}

// 读取最新的attestors信息
function getLatestAttestors() {
  try {
    if (fs.existsSync(ATTESTORS_FILE)) {
      return JSON.parse(fs.readFileSync(ATTESTORS_FILE, 'utf8'));
    }
    return null;
  } catch (e) {
    console.error('读取attestors文件失败:', e.message);
    return null;
  }
}

// 读取任务历史
function getTasksHistory() {
  try {
    if (fs.existsSync(TASKS_FILE)) {
      return JSON.parse(fs.readFileSync(TASKS_FILE, 'utf8'));
    }
    return [];
  } catch (e) {
    console.error('读取任务历史文件失败:', e.message);
    return [];
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  createNewTask().catch(console.error);
}

module.exports = { 
  createNewTask, 
  getLatestAttestors, 
  getTasksHistory, 
  CONFIG,
  generateRandomSeed,
  getCurrentTimestamp
};
