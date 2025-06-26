# MeChain Attestor 调用工具

## 📋 概述

本工具用于调用 MeChain 网络中的 Attestors，通过 `createClaimOnAttestor` 方法创建 claims 和生成 zero-knowledge proofs (ZKPs)。

**功能特性：**
- 🔗 调用多个 Attestors 进行 claim 创建
- 📊 使用 Binance API 作为数据提供者
- 🔐 生成签名和 ZKP 证明
- 💾 保存结果用于合约验证
- 🎨 中文界面和彩色输出

## 🚀 快速开始

### 1. 快速调用所有 Attestors
```bash
./quick-call-attestors.sh
```

### 2. 交互式管理
```bash
./attestor-manager.sh
```

## 📖 详细功能

### Attestor 调用

#### 1. 自动调用所有 Attestors
```bash
node call-attestors.js
```
- 使用最新任务的 attestors
- 自动生成 Binance API 的 ProviderParams
- 调用所有 attestors 创建 claims
- 生成 ZKP 证明

#### 2. 指定任务ID调用
```bash
node call-attestors.js <任务ID>
```

### 结果查看

#### 1. 查看最新结果
```bash
node view-proofs.js
```

#### 2. 查看历史记录
```bash
node view-proofs.js history
```

#### 3. 查看详细信息
```bash
node view-proofs.js detail <记录编号>
```

#### 4. 导出验证文件
```bash
node view-proofs.js export
```

## 🔧 技术实现

### ProviderParams 生成

针对 Binance API (`https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT`) 生成的参数：

```javascript
{
  method: 'GET',
  url: 'https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT',
  responseMatches: [
    {
      type: 'regex',
      value: '{"symbol":"ETHUSDT","price":"(?<price>.*?)"}'
    }
  ],
  responseRedactions: [
    {
      regex: '{"symbol":"ETHUSDT","price":"(?<price>.*?)"}'
    }
  ],
  geoLocation: '',
  body: '',
  paramValues: {},
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
  }
}
```

### createClaimOnAttestor 调用

```javascript
const response = await createClaimOnAttestor({
  name: 'http',
  params: providerParams,
  secretParams: {
    headers: providerParams.headers,
    cookieStr: '',
    authorisationHeader: ''
  },
  ownerPrivateKey: '0x' + privateKey,
  client: attestorClient
});
```

### Proof 转换

使用 `transformForOnchain` 将 attestor 响应转换为链上验证格式：

```javascript
const proof = await transformForOnchain(response);
```

## 📁 数据存储

### 文件结构
```
attestor-calls/
├── data/
│   ├── latest-proofs.json          # 最新的 proof 结果
│   ├── attestor-proofs.json        # 历史记录
│   └── proofs-for-verification.json # 导出的验证文件
├── call-attestors.js               # 主调用脚本
├── view-proofs.js                  # 结果查看脚本
├── attestor-manager.sh             # 交互式管理
└── quick-call-attestors.sh         # 快速调用
```

### 数据格式

#### latest-proofs.json
```json
{
  "taskId": "5",
  "timestamp": "2025-06-27T03:00:00.000Z",
  "providerParams": {
    "method": "GET",
    "url": "https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT",
    "responseMatches": [...]
  },
  "binanceData": {
    "symbol": "ETHUSDT",
    "price": "2424.44000000"
  },
  "totalAttestors": 2,
  "successfulCalls": 2,
  "failedCalls": 0,
  "results": [
    {
      "attestorIndex": 0,
      "attestorAddress": "0xaef2Ba08B0f836c81ed975452507825B5497e62f",
      "attestorHost": "wss://devint-reclaim0.mechain.tech/ws",
      "success": true,
      "response": {...},
      "proof": {
        "identifier": "0x...",
        "claimData": {...},
        "signatures": ["0x..."],
        "witnesses": [...]
      },
      "timestamp": "2025-06-27T03:00:00.000Z"
    }
  ]
}
```

#### proofs-for-verification.json
```json
{
  "taskId": "5",
  "timestamp": "2025-06-27T03:00:00.000Z",
  "proofs": [
    {
      "identifier": "0x...",
      "claimData": {...},
      "signatures": ["0x..."],
      "witnesses": [...]
    }
  ],
  "metadata": {
    "totalAttestors": 2,
    "successfulProofs": 2,
    "binanceData": {
      "symbol": "ETHUSDT",
      "price": "2424.44000000"
    }
  }
}
```

## 📊 示例输出

### 调用成功示例
```
🚀 开始调用Attestors进行claim创建...

🔍 正在测试Binance API连接...
✅ API连接成功! 当前ETH价格: $2424.44

📋 正在生成ProviderParams...
✅ ProviderParams生成完成

📁 正在读取任务数据...
✅ 任务数据读取成功! 任务ID: 5
📊 找到 2 个Attestors

👥 将要调用的Attestors:
🔸 Attestor 1:
   地址: 0xaef2Ba08B0f836c81ed975452507825B5497e62f
   Host: wss://devint-reclaim0.mechain.tech/ws

🔸 Attestor 2:
   地址: 0x9D27Ffaa734bE554834945Aff5F3Fa6DA41db132
   Host: wss://devint-reclaim1.mechain.tech/ws

============================================================
🔄 开始调用Attestors...
============================================================

📞 调用 Attestor 1/2:
🔗 正在连接到 Attestor 1: wss://devint-reclaim0.mechain.tech/ws
📋 正在请求 Attestor 1 创建claim...
✅ Attestor 1 响应成功!

📞 调用 Attestor 2/2:
🔗 正在连接到 Attestor 2: wss://devint-reclaim1.mechain.tech/ws
📋 正在请求 Attestor 2 创建claim...
✅ Attestor 2 响应成功!

============================================================
📊 调用结果摘要
============================================================
✅ 成功调用: 2/2
❌ 失败调用: 0/2

🔸 Attestor 1 (wss://devint-reclaim0.mechain.tech/ws):
   状态: ✅ 成功
   Proof生成: ✅ 完成

🔸 Attestor 2 (wss://devint-reclaim1.mechain.tech/ws):
   状态: ✅ 成功
   Proof生成: ✅ 完成

💾 正在保存结果到文件...
✅ 结果已保存到:
   最新结果: data/latest-proofs.json
   历史记录: data/attestor-proofs.json

============================================================
🎉 Attestor调用完成!
============================================================
```

## 🔄 工作流程

### 典型使用流程

1. **确保有可用任务**
   ```bash
   cd ../task-management && ./quick-create-task.sh
   ```

2. **调用 Attestors**
   ```bash
   cd ../attestor-calls && ./quick-call-attestors.sh
   ```

3. **查看结果**
   ```bash
   node view-proofs.js
   ```

4. **导出验证文件**
   ```bash
   node view-proofs.js export
   ```

5. **用于合约验证**
   - 使用 `data/proofs-for-verification.json` 文件
   - 包含所有成功生成的 proofs
   - 可直接用于 `verifyProofs` 合约调用

## 🛠️ 故障排除

### 常见问题

1. **Attestor 连接失败**
   - 检查网络连接
   - 确认 attestor 服务是否在线
   - 检查 WebSocket 连接

2. **Binance API 调用失败**
   - 检查网络连接
   - 确认 API 地址是否正确
   - 检查是否被限流

3. **任务数据未找到**
   - 先在 task-management 目录创建任务
   - 确认 latest-attestors.json 文件存在

4. **依赖问题**
   ```bash
   cd .. && npm install
   ```

## 📞 下一步使用

生成的 proof 数据可以用于：

1. **合约验证**
   - 使用 `proofs-for-verification.json`
   - 调用 ReclaimTask 合约的 `verifyProofs` 方法
   - 完成链上验证流程

2. **数据分析**
   - 分析 attestor 响应时间
   - 监控成功率
   - 追踪价格数据变化

3. **集成开发**
   - 导入模块使用相关函数
   - 自定义 ProviderParams
   - 扩展支持更多数据源
