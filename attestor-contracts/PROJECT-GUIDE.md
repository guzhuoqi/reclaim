# MeChain 合约管理工具集

## 📋 项目概述

本项目提供了一套完整的工具来管理 MeChain 测试网上的 Governance 和 ReclaimTask 合约。

**合约信息：**
- **Governance 合约**: `0x0d113bDe369DC8Df8e24760473bB3C4965a17078`
- **ReclaimTask 合约**: `0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820`
- **网络**: MeChain 测试网 (`https://testnet-rpc.mechain.tech`)

## 📁 项目结构

```
attestor-contracts/
├── node-query/                    # 节点查询功能
│   ├── view-registered-nodes.js   # 查看已注册节点脚本
│   ├── view-nodes.sh              # 交互式节点查询
│   ├── quick-view-nodes.sh        # 快速查看节点
│   └── node-query-guide.md        # 节点查询使用说明
│
├── task-management/               # 任务管理功能
│   ├── create-task.js             # 创建任务脚本
│   ├── view-tasks.js              # 查看任务脚本
│   ├── task-manager.sh            # 交互式任务管理
│   ├── quick-create-task.sh       # 快速创建任务
│   ├── data/                      # 数据存储目录
│   │   ├── latest-attestors.json  # 最新attestors信息
│   │   └── tasks-history.json     # 任务历史记录
│   └── README.md                  # 任务管理使用说明
│
├── attestor-calls/                # Attestor调用功能
│   ├── call-attestors.js          # 调用attestors脚本
│   ├── view-proofs.js             # 查看proofs脚本
│   ├── attestor-manager.sh        # 交互式attestor管理
│   ├── quick-call-attestors.sh    # 快速调用attestors
│   ├── data/                      # 数据存储目录
│   │   ├── latest-proofs.json     # 最新proofs信息
│   │   ├── attestor-proofs.json   # Proofs历史记录
│   │   └── proofs-for-verification.json # 导出的验证文件
│   └── README.md                  # Attestor调用使用说明
│
├── proof-verification/            # Proof验证功能
│   ├── verify-proofs.js           # 验证proofs脚本
│   ├── view-verification-results.js # 查看验证结果脚本
│   ├── verification-manager.sh    # 交互式验证管理
│   ├── quick-verify-proofs.sh     # 快速验证proofs
│   ├── data/                      # 数据存储目录
│   │   ├── latest-verification.json # 最新验证结果
│   │   ├── verification-results.json # 验证历史记录
│   │   └── verification-analysis.json # 导出的分析数据
│   └── README.md                  # Proof验证使用说明
│
├── scripts/                       # 原有Hardhat脚本
├── .env                          # 环境变量配置
└── PROJECT-GUIDE.md              # 本文档
```

## 🚀 快速开始

### 1. 安装依赖
```bash
npm install
```

### 2. 配置环境
确保 `.env` 文件包含正确的私钥：
```
PRIVATE_KEY=your_private_key_here
```

## 📖 功能模块

### 🔍 节点查询 (node-query/)

查看 Governance 合约中已注册的节点信息。

**快速使用：**
```bash
cd node-query
./quick-view-nodes.sh
```

**交互式使用：**
```bash
cd node-query
./view-nodes.sh
```

**功能特性：**
- 查看所有已注册节点
- 显示节点详细信息（地址、Host、质押金额、状态）
- 支持查看特定节点
- 中文界面，彩色输出

### 📋 任务管理 (task-management/)

管理 ReclaimTask 合约中的任务创建和查看。

**快速创建任务：**
```bash
cd task-management
./quick-create-task.sh
```

**交互式管理：**
```bash
cd task-management
./task-manager.sh
```

**功能特性：**
- 创建新任务（调用 createNewTaskRequest）
- 自动保存 attestors 信息到本地文件
- 查看任务详情和状态
- 任务历史记录管理
- 支持自定义参数

### 🔄 Attestor 调用 (attestor-calls/)

调用 Attestor 节点生成 zero-knowledge proofs。

**快速调用 Attestors：**
```bash
cd attestor-calls
./quick-call-attestors.sh
```

**交互式管理：**
```bash
cd attestor-calls
./attestor-manager.sh
```

**功能特性：**
- 直接 RPC 调用 attestor 节点
- 使用 Binance API 作为数据提供者
- 生成 ProviderParams 和 SecretParams
- 保存 attestor 返回的 proofs
- 导出验证文件

### 🔐 Proof 验证 (proof-verification/)

调用 ReclaimTask 合约验证 attestor 生成的 proofs。

**快速验证 Proofs：**
```bash
cd proof-verification
./quick-verify-proofs.sh
```

**交互式管理：**
```bash
cd proof-verification
./verification-manager.sh
```

**功能特性：**
- 调用 `verifyProofs` 合约方法
- 自动支付验证费用
- 保存验证入参、RPC请求和结果
- 检查共识状态
- 导出分析数据

## 💾 数据管理

### Attestors 数据保存

创建任务后，attestors 信息会自动保存到：

1. **最新信息**: `task-management/data/latest-attestors.json`
2. **历史记录**: `task-management/data/tasks-history.json`

### 数据格式示例

```json
{
  "taskId": "5",
  "timestamp": "2025-06-27T02:36:40.000Z",
  "seed": "0x4c9025d28ce4e152ee3412511752a1a7e45f1b19c39b8c8141f4b07d60d4198d",
  "requestTimestamp": 1750962991,
  "attestors": [
    {
      "address": "0xaef2Ba08B0f836c81ed975452507825B5497e62f",
      "host": "wss://devint-reclaim0.mechain.tech/ws"
    },
    {
      "address": "0x9D27Ffaa734bE554834945Aff5F3Fa6DA41db132",
      "host": "wss://devint-reclaim1.mechain.tech/ws"
    }
  ]
}
```

## 🔄 工作流程

### 典型使用流程

1. **查看已注册节点**
   ```bash
   cd node-query && ./quick-view-nodes.sh
   ```

2. **创建新任务**
   ```bash
   cd task-management && ./quick-create-task.sh
   ```

3. **调用 Attestors 生成 Proofs**
   ```bash
   cd attestor-calls && ./quick-call-attestors.sh
   ```

4. **验证 Proofs**
   ```bash
   cd proof-verification && ./quick-verify-proofs.sh
   ```

5. **查看完整流程结果**
   ```bash
   cd task-management && node view-tasks.js
   cd attestor-calls && node view-proofs.js
   cd proof-verification && node view-verification-results.js
   ```

## 🛠️ 高级功能

### 使用 Hardhat

除了自定义脚本，您还可以使用原有的 Hardhat 任务：

```bash
# 查看节点
npx hardhat get-attestors --network mechain-testnet

# 创建任务
npx hardhat create-task-request --network mechain-testnet
```

### 自定义参数

在交互式脚本中，您可以：
- 自定义 seed 值
- 自定义时间戳
- 查看特定任务ID
- 管理历史记录

## 📊 监控和调试

### 查看合约状态
```bash
# 查看当前任务
cd task-management && node view-tasks.js

# 查看特定任务
cd task-management && node view-tasks.js task 5

# 查看本地数据
cd task-management && node view-tasks.js local

# 查看历史记录
cd task-management && node view-tasks.js history
```

### 网络信息
- **链ID**: 5151
- **区块浏览器**: https://testnet-scan.mechain.tech
- **RPC**: https://testnet-rpc.mechain.tech

## 🔧 故障排除

### 常见问题

1. **网络连接问题**
   - 检查网络连接
   - 确认 RPC 地址是否可访问

2. **合约调用失败**
   - 检查合约地址是否正确
   - 确认账户余额是否足够支付 gas

3. **权限问题**
   ```bash
   chmod +x *.sh
   ```

4. **依赖问题**
   ```bash
   npm install
   ```

## 📞 下一步开发

基于当前的工具集，您可以：

1. **集成 Attestors 调用**
   - 使用保存的 attestors 信息
   - 实现与 attestors 的通信
   - 处理验证响应

2. **扩展功能**
   - 添加更多合约交互
   - 实现自动化工作流
   - 添加监控和告警

3. **优化体验**
   - 改进错误处理
   - 添加更多配置选项
   - 实现批量操作

## 📝 贡献指南

如需添加新功能：

1. 在相应的功能目录下创建新脚本
2. 更新相关的 README 文档
3. 确保脚本具有适当的错误处理
4. 添加中文界面和彩色输出
5. 测试所有功能正常工作
