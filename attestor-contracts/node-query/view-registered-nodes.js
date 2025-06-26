const { ethers } = require('ethers');
const fs = require('fs');

// 读取配置信息
const path = require('path');
const addresses = require('../scripts/addresses.json');

const CONFIG = {
  contractAddress: addresses.governance,
  networkURL: 'https://testnet-rpc.mechain.tech',
  privateKey: 'd716026fb6fce2b47a911ef44d36d7e07fd6b09037c0b3d7121f20061388cba6'
};

// Governance合约ABI (只包含我们需要的方法)
const GOVERNANCE_ABI = [
  "function getAttestors() external view returns (string[] memory keys, address[] memory addresses)",
  "function getAttestor(string memory _key) external view returns (address)",
  "function stakedAmounts(address) external view returns (uint256)",
  "function pendingRewards(address) external view returns (uint256)",
  "function minimumStake() external view returns (uint256)",
  "function totalStaked() external view returns (uint256)"
];

async function main() {
  try {
    console.log('🔗 正在连接到 MeChain 测试网...');
    
    // 创建provider和wallet
    const provider = new ethers.JsonRpcProvider(CONFIG.networkURL);
    const wallet = new ethers.Wallet(CONFIG.privateKey, provider);
    
    // 连接到合约
    const contract = new ethers.Contract(CONFIG.contractAddress, GOVERNANCE_ABI, wallet);
    
    console.log(`📋 合约地址: ${CONFIG.contractAddress}`);
    console.log(`🌐 网络: ${CONFIG.networkURL}`);
    console.log(`👤 查询地址: ${wallet.address}\n`);
    
    // 获取基本信息
    console.log('📊 正在获取合约基本信息...');
    const minimumStake = await contract.minimumStake();
    const totalStaked = await contract.totalStaked();
    
    console.log(`最小质押要求: ${ethers.formatEther(minimumStake)} ETH`);
    console.log(`总质押金额: ${ethers.formatEther(totalStaked)} ETH\n`);
    
    // 获取所有已注册的节点
    console.log('🔍 正在查询已注册的节点...');
    const [keys, addresses] = await contract.getAttestors();
    
    console.log('='.repeat(60));
    console.log('📋 已注册节点列表');
    console.log('='.repeat(60));
    console.log(`总共找到 ${keys.length} 个已注册的节点\n`);
    
    if (keys.length === 0) {
      console.log('❌ 暂无已注册的节点');
    } else {
      for (let i = 0; i < keys.length; i++) {
        console.log(`🔸 节点 ${i + 1}:`);
        console.log(`   Key: ${keys[i]}`);
        console.log(`   地址: ${addresses[i]}`);
        
        try {
          // 获取质押金额
          const stakedAmount = await contract.stakedAmounts(addresses[i]);
          console.log(`   质押金额: ${ethers.formatEther(stakedAmount)} ETH`);
          
          // 获取待领取奖励
          const pendingRewards = await contract.pendingRewards(addresses[i]);
          console.log(`   待领取奖励: ${ethers.formatEther(pendingRewards)} ETH`);
          
          // 检查是否满足最小质押要求
          const isEligible = stakedAmount >= minimumStake;
          console.log(`   状态: ${isEligible ? '✅ 符合要求' : '❌ 质押不足'}`);
          
        } catch (error) {
          console.log(`   ⚠️  获取详细信息失败: ${error.message}`);
        }
        
        console.log('');
      }
    }
    
    console.log('='.repeat(60));
    console.log('✅ 查询完成');
    console.log('='.repeat(60));
    
  } catch (error) {
    console.error('❌ 发生错误:', error.message);
    if (error.code) {
      console.error(`错误代码: ${error.code}`);
    }
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { main, CONFIG };
