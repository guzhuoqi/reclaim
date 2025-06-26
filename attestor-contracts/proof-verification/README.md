# MeChain Proof 验证工具

## 📋 概述

本工具用于调用 MeChain ReclaimTask 合约的 `verifyProofs` 方法，验证 Attestors 生成的 zero-knowledge proofs。

**功能特性：**
- 🔐 调用 `verifyProofs` 合约方法
- 💾 保存验证入参、RPC请求和链上结果
- 📊 完整的验证流程记录
- 🎨 中文界面和彩色输出

## 🚀 快速开始

### 1. 快速验证 Proofs
```bash
./quick-verify-proofs.sh
```

### 2. 交互式管理
```bash
./verification-manager.sh
```

## 📖 详细功能

### Proof 验证

#### 1. 自动验证（推荐）
```bash
node verify-proofs.js
```
- 使用最新任务的 proofs
- 自动转换数据格式
- 支付验证费用
- 调用 `verifyProofs` 方法

#### 2. 指定任务ID验证
```bash
node verify-proofs.js <任务ID>
```

### 结果查看

#### 1. 查看最新结果
```bash
node view-verification-results.js
```

#### 2. 查看历史记录
```bash
node view-verification-results.js history
```

#### 3. 查看详细信息
```bash
node view-verification-results.js detail <记录编号>
```

#### 4. 导出分析数据
```bash
node view-verification-results.js export
```

## 🔧 技术实现

### verifyProofs 方法调用

```javascript
await contract.verifyProofs(contractProofs, taskId, {
  value: verificationCost
});
```

### Proof 数据结构转换

将 Attestor 返回的数据转换为合约需要的格式：

```javascript
// 输入：Attestor 返回的数据
{
  claim: { identifier, owner, timestampS, epoch, provider, parameters, context },
  signatures: { claimSignature, resultSignature, attestorAddress }
}

// 输出：合约需要的 Proof 结构
{
  claimInfo: {
    provider: string,
    parameters: string,
    context: string
  },
  signedClaim: {
    claim: {
      identifier: bytes32,
      owner: address,
      timestampS: uint32,
      epoch: uint32
    },
    signatures: bytes[]
  }
}
```

### 验证费用处理

```javascript
// 从 Governance 合约获取验证费用
const verificationCost = await governanceContract.verificationCost();

// 在调用时支付费用
await contract.verifyProofs(proofs, taskId, { value: verificationCost });
```

## 📁 数据存储

### 文件结构
```
proof-verification/
├── data/
│   ├── latest-verification.json      # 最新验证结果
│   ├── verification-results.json     # 历史记录
│   └── verification-analysis.json    # 导出的分析数据
├── verify-proofs.js                  # 主验证脚本
├── view-verification-results.js      # 结果查看脚本
├── verification-manager.sh           # 交互式管理
└── quick-verify-proofs.sh           # 快速验证
```

### 数据格式

#### latest-verification.json
```json
{
  "taskId": "5",
  "timestamp": "2025-06-27T03:30:00.000Z",
  "transactionHash": "0xabcd1234...",
  "verificationCost": "1000000000000000000",
  "success": true,
  "consensusReached": true,
  "inputData": {
    "proofsCount": 2,
    "proofs": [
      {
        "claimInfo": {
          "provider": "http",
          "parameters": "{\"method\":\"GET\",\"url\":\"https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT\"}",
          "context": ""
        },
        "signedClaim": {
          "claim": {
            "identifier": "0x1798bd260ab3fb35e1...",
            "owner": "0xe44973079dfA1E56F6A5de82C167F7e6fD610cc5",
            "timestampS": 1719456600,
            "epoch": 1
          },
          "signatures": ["0x4a5b6c7d..."]
        }
      }
    ]
  },
  "rpcRequest": {
    "method": "verifyProofs",
    "params": {
      "proofs": [...],
      "taskId": 5,
      "value": "1000000000000000000"
    }
  }
}
```

#### verification-analysis.json
```json
{
  "taskId": "5",
  "timestamp": "2025-06-27T03:30:00.000Z",
  "success": true,
  "consensusReached": true,
  "transactionHash": "0xabcd1234...",
  "verificationCost": "1000000000000000000",
  "proofsCount": 2,
  "proofsAnalysis": [
    {
      "provider": "http",
      "owner": "0xe44973079dfA1E56F6A5de82C167F7e6fD610cc5",
      "timestampS": 1719456600,
      "epoch": 1,
      "signaturesCount": 1
    }
  ]
}
```

## 📊 示例输出

### 验证成功示例
```
🚀 开始验证Proofs...

📋 ReclaimTask 合约地址: 0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820
🌐 网络: https://testnet-rpc.mechain.tech
👤 发送地址: 0xe44973079dfA1E56F6A5de82C167F7e6fD610cc5

📁 正在读取Attestor生成的Proofs...
✅ 读取成功! 任务ID: 5
📊 找到 2 个Proofs

🎯 目标任务ID: 5

🔍 检查任务状态...
✅ 任务尚未被验证，可以继续

🔄 正在转换Proof数据格式...
📋 处理Proof 1:
   Attestor: wss://devint-reclaim0.mechain.tech/ws
   Claim ID: 0x1798bd260ab3fb35e1...
   ✅ Proof 1 转换完成

📋 处理Proof 2:
   Attestor: wss://devint-reclaim1.mechain.tech/ws
   Claim ID: 0x22f6f750f4fd2a5088...
   ✅ Proof 2 转换完成

✅ 总共转换了 2 个Proofs

💰 正在获取验证费用...
✅ 验证费用: 0.001000 ETH

📋 验证参数:
   任务ID: 5
   Proofs数量: 2
   验证费用: 0.001000 ETH

============================================================
🔐 正在调用 verifyProofs 方法...
============================================================
📝 交易哈希: 0xabcd1234...
⏳ 等待交易确认...
✅ 交易已确认! Gas使用量: 250000

🔍 检查验证结果...
============================================================
🎉 验证完成!
============================================================
任务ID: 5
共识状态: ✅ 已达成
交易哈希: 0xabcd1234...
Gas使用量: 250000
验证费用: 0.001000 ETH

💾 正在保存验证结果...
✅ 验证结果已保存到:
   最新结果: data/latest-verification.json
   历史记录: data/verification-results.json

============================================================
✅ 验证流程完成!
============================================================
```

## 🔄 工作流程

### 典型使用流程

1. **确保有可用的 Proofs**
   ```bash
   cd ../attestor-calls && ./quick-call-attestors.sh
   ```

2. **验证 Proofs**
   ```bash
   cd ../proof-verification && ./quick-verify-proofs.sh
   ```

3. **查看验证结果**
   ```bash
   node view-verification-results.js
   ```

4. **导出分析数据**
   ```bash
   node view-verification-results.js export
   ```

## 🛠️ 故障排除

### 常见问题

1. **任务已被验证**
   - 错误: "Task already processed"
   - 解决: 创建新任务或使用不同的任务ID

2. **验证费用不足**
   - 错误: "Verification underpriced"
   - 解决: 确保账户有足够的ETH支付验证费用

3. **Proofs数据未找到**
   - 错误: "未找到attestor proofs文件"
   - 解决: 先运行 attestor-calls 脚本生成 proofs

4. **签名验证失败**
   - 检查 proof 数据格式是否正确
   - 确认 attestor 签名有效

## 📞 验证完成后

验证成功后：

1. **任务状态更新**
   - `consensusReached[taskId]` 设置为 `true`
   - 任务标记为已处理

2. **Attestor 奖励**
   - 参与验证的 attestors 获得奖励
   - 通过 Governance 合约分发

3. **数据记录**
   - 完整的验证流程记录
   - 可用于审计和分析

## 🔗 相关合约

- **ReclaimTask**: `0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820`
- **Governance**: `0x0d113bDe369DC8Df8e24760473bB3C4965a17078`
- **网络**: MeChain 测试网
