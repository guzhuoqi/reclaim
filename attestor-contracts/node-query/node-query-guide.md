# MeChain Governance 节点查询工具使用说明

## 📋 概述

本工具用于查询 MeChain Governance 合约中已注册的节点信息。

**合约信息：**
- 合约地址: `0x0d113bDe369DC8Df8e24760473bB3C4965a17078`
- 网络: MeChain 测试网 (`https://testnet-rpc.mechain.tech`)

## 🚀 快速开始

### 1. 安装依赖
```bash
npm install
```

### 2. 快速查看所有节点
```bash
./quick-view-nodes.sh
```

## 📖 详细使用方法

### 方法一：使用 Node.js 脚本（推荐）

#### 查看所有已注册节点
```bash
node scripts/view-registered-nodes.js
```

#### 使用交互式菜单
```bash
./view-nodes.sh
```

### 方法二：使用 Hardhat

#### 查看所有节点
```bash
npx hardhat get-attestors --network mechain-testnet
```

#### 查看特定节点
```bash
npx hardhat get-attestor --network mechain-testnet -- "节点Key"
```

## 📊 输出信息说明

脚本会显示以下信息：

### 合约基本信息
- 最小质押要求
- 总质押金额
- 查询地址

### 节点详细信息
- **Key**: 节点的唯一标识符
- **地址**: 节点的以太坊地址
- **质押金额**: 节点当前质押的ETH数量
- **待领取奖励**: 节点可领取的奖励金额
- **状态**: 是否符合最小质押要求

## 🔧 配置文件

### .env 文件
```
PRIVATE_KEY=d716026fb6fce2b47a911ef44d36d7e07fd6b09037c0b3d7121f20061388cba6
```

### addresses.json 文件
```json
{
  "governance": "0x0d113bDe369DC8Df8e24760473bB3C4965a17078",
  "task": "0xBb6817f565e5bc42B4458B0287e99289E2425030"
}
```

## 📝 示例输出

```
🔗 正在连接到 MeChain 测试网...
📋 合约地址: 0x0d113bDe369DC8Df8e24760473bB3C4965a17078
🌐 网络: https://testnet-rpc.mechain.tech
👤 查询地址: 0xe44973079dfA1E56F6A5de82C167F7e6fD610cc5

📊 正在获取合约基本信息...
最小质押要求: 10.0 ETH
总质押金额: 20.0 ETH

============================================================
📋 已注册节点列表
============================================================
总共找到 2 个已注册的节点

🔸 节点 1:
   Key: wss://devint-reclaim0.mechain.tech/ws
   地址: 0xaef2Ba08B0f836c81ed975452507825B5497e62f
   质押金额: 10.0 ETH
   待领取奖励: 0.0 ETH
   状态: ✅ 符合要求

🔸 节点 2:
   Key: wss://devint-reclaim1.mechain.tech/ws
   地址: 0x9D27Ffaa734bE554834945Aff5F3Fa6DA41db132
   质押金额: 10.0 ETH
   待领取奖励: 0.0 ETH
   状态: ✅ 符合要求
```

## 🚀 快速使用

**最简单的方式（推荐）：**
```bash
cd attestor-contracts
./quick-view-nodes.sh
```

**交互式菜单：**
```bash
./view-nodes.sh
```

**使用 Hardhat：**
```bash
npx hardhat get-attestors --network mechain-testnet
```

## 🛠️ 故障排除

### 常见问题

1. **模块未找到错误**
   ```bash
   npm install
   ```

2. **网络连接问题**
   - 检查网络连接
   - 确认 RPC 地址是否正确

3. **权限问题**
   ```bash
   chmod +x *.sh
   ```

## 📞 支持

如有问题，请检查：
1. 网络连接是否正常
2. 合约地址是否正确
3. 私钥是否有效
4. 依赖是否已正确安装
