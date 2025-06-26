const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

// 配置信息
const CONFIG = {
  reclaimTaskAddress: '0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820',
  networkURL: 'https://testnet-rpc.mechain.tech',
  privateKey: 'd716026fb6fce2b47a911ef44d36d7e07fd6b09037c0b3d7121f20061388cba6'
};

// ReclaimTask合约ABI
const RECLAIM_TASK_ABI = [
  "function currentTask() public view returns (uint32)",
  "function fetchTask(uint32 taskId) public view returns (tuple(uint32 id, uint32 timestampStart, uint32 timestampEnd, tuple(address addr, string host)[] attestors))",
  "function requiredAttestors() public view returns (uint8)",
  "function taskDurationS() public view returns (uint32)",
  "function consensusReached(uint32) public view returns (bool)"
];

// 数据文件路径
const DATA_DIR = path.join(__dirname, 'data');
const ATTESTORS_FILE = path.join(DATA_DIR, 'latest-attestors.json');
const TASKS_FILE = path.join(DATA_DIR, 'tasks-history.json');

async function viewCurrentTask() {
  try {
    console.log('🔗 正在连接到 MeChain 测试网...');
    
    const provider = new ethers.JsonRpcProvider(CONFIG.networkURL);
    const wallet = new ethers.Wallet(CONFIG.privateKey, provider);
    const contract = new ethers.Contract(CONFIG.reclaimTaskAddress, RECLAIM_TASK_ABI, wallet);
    
    console.log(`📋 ReclaimTask 合约地址: ${CONFIG.reclaimTaskAddress}`);
    console.log(`🌐 网络: ${CONFIG.networkURL}\n`);
    
    // 获取当前任务信息
    const currentTaskId = await contract.currentTask();
    console.log(`当前任务ID: ${currentTaskId.toString()}\n`);
    
    if (currentTaskId > 0) {
      const taskDetails = await contract.fetchTask(currentTaskId);
      const consensusReached = await contract.consensusReached(currentTaskId);
      
      console.log('='.repeat(60));
      console.log('📋 当前任务详情');
      console.log('='.repeat(60));
      console.log(`任务ID: ${taskDetails.id.toString()}`);
      console.log(`开始时间: ${new Date(Number(taskDetails.timestampStart) * 1000).toLocaleString()}`);
      console.log(`结束时间: ${new Date(Number(taskDetails.timestampEnd) * 1000).toLocaleString()}`);
      console.log(`共识状态: ${consensusReached ? '✅ 已达成' : '⏳ 进行中'}`);
      console.log(`Attestors数量: ${taskDetails.attestors.length}\n`);
      
      console.log('👥 任务Attestors:');
      taskDetails.attestors.forEach((attestor, index) => {
        console.log(`🔸 Attestor ${index + 1}:`);
        console.log(`   地址: ${attestor.addr}`);
        console.log(`   Host: ${attestor.host}`);
        console.log('');
      });
    } else {
      console.log('❌ 暂无任务');
    }
    
    console.log('='.repeat(60));
    
  } catch (error) {
    console.error('❌ 查看任务时发生错误:', error.message);
  }
}

async function viewTaskById(taskId) {
  try {
    console.log('🔗 正在连接到 MeChain 测试网...');
    
    const provider = new ethers.JsonRpcProvider(CONFIG.networkURL);
    const wallet = new ethers.Wallet(CONFIG.privateKey, provider);
    const contract = new ethers.Contract(CONFIG.reclaimTaskAddress, RECLAIM_TASK_ABI, wallet);
    
    console.log(`📋 查询任务ID: ${taskId}\n`);
    
    const taskDetails = await contract.fetchTask(taskId);
    const consensusReached = await contract.consensusReached(taskId);
    
    console.log('='.repeat(60));
    console.log(`📋 任务 ${taskId} 详情`);
    console.log('='.repeat(60));
    console.log(`任务ID: ${taskDetails.id.toString()}`);
    console.log(`开始时间: ${new Date(Number(taskDetails.timestampStart) * 1000).toLocaleString()}`);
    console.log(`结束时间: ${new Date(Number(taskDetails.timestampEnd) * 1000).toLocaleString()}`);
    console.log(`共识状态: ${consensusReached ? '✅ 已达成' : '⏳ 进行中'}`);
    console.log(`Attestors数量: ${taskDetails.attestors.length}\n`);
    
    console.log('👥 任务Attestors:');
    taskDetails.attestors.forEach((attestor, index) => {
      console.log(`🔸 Attestor ${index + 1}:`);
      console.log(`   地址: ${attestor.addr}`);
      console.log(`   Host: ${attestor.host}`);
      console.log('');
    });
    
    console.log('='.repeat(60));
    
  } catch (error) {
    console.error('❌ 查看任务时发生错误:', error.message);
  }
}

function viewLocalAttestors() {
  console.log('📁 查看本地保存的Attestors信息\n');
  
  if (fs.existsSync(ATTESTORS_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(ATTESTORS_FILE, 'utf8'));
      
      console.log('='.repeat(60));
      console.log('💾 最新保存的Attestors信息');
      console.log('='.repeat(60));
      console.log(`任务ID: ${data.taskId}`);
      console.log(`保存时间: ${new Date(data.timestamp).toLocaleString()}`);
      console.log(`请求时间戳: ${data.requestTimestamp} (${new Date(data.requestTimestamp * 1000).toLocaleString()})`);
      console.log(`Seed: ${data.seed}`);
      console.log(`Attestors数量: ${data.attestors.length}\n`);
      
      console.log('👥 Attestors列表:');
      data.attestors.forEach((attestor, index) => {
        console.log(`🔸 Attestor ${index + 1}:`);
        console.log(`   地址: ${attestor.address}`);
        console.log(`   Host: ${attestor.host}`);
        console.log('');
      });
      
      console.log('='.repeat(60));
      
    } catch (e) {
      console.error('❌ 读取本地文件失败:', e.message);
    }
  } else {
    console.log('❌ 未找到本地Attestors文件');
    console.log('💡 请先创建一个任务来生成Attestors信息');
  }
}

function viewTasksHistory() {
  console.log('📚 查看任务历史记录\n');
  
  if (fs.existsSync(TASKS_FILE)) {
    try {
      const history = JSON.parse(fs.readFileSync(TASKS_FILE, 'utf8'));
      
      if (history.length === 0) {
        console.log('❌ 暂无任务历史记录');
        return;
      }
      
      console.log('='.repeat(60));
      console.log(`📚 任务历史记录 (共 ${history.length} 个任务)`);
      console.log('='.repeat(60));
      
      history.forEach((task, index) => {
        console.log(`📋 任务 ${index + 1}:`);
        console.log(`   任务ID: ${task.taskId}`);
        console.log(`   创建时间: ${new Date(task.timestamp).toLocaleString()}`);
        console.log(`   Attestors数量: ${task.attestors.length}`);
        const seedStr = typeof task.seed === 'string' ? task.seed : JSON.stringify(task.seed);
        console.log(`   Seed: ${seedStr.substring(0, 20)}...`);
        console.log('');
      });
      
      console.log('='.repeat(60));
      
    } catch (e) {
      console.error('❌ 读取历史文件失败:', e.message);
    }
  } else {
    console.log('❌ 未找到任务历史文件');
    console.log('💡 请先创建一个任务来生成历史记录');
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    viewCurrentTask().catch(console.error);
  } else if (args[0] === 'local') {
    viewLocalAttestors();
  } else if (args[0] === 'history') {
    viewTasksHistory();
  } else if (args[0] === 'task' && args[1]) {
    viewTaskById(parseInt(args[1])).catch(console.error);
  } else {
    console.log('用法:');
    console.log('  node view-tasks.js          # 查看当前任务');
    console.log('  node view-tasks.js local    # 查看本地保存的attestors');
    console.log('  node view-tasks.js history  # 查看任务历史');
    console.log('  node view-tasks.js task <id> # 查看指定任务');
  }
}

module.exports = { 
  viewCurrentTask, 
  viewTaskById, 
  viewLocalAttestors, 
  viewTasksHistory 
};
