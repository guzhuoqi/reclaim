# MeChain ReclaimTask 任务管理工具

## 📋 概述

本工具用于管理 MeChain ReclaimTask 合约中的任务创建和查看功能。

**合约信息：**
- ReclaimTask 合约地址: `0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820`
- Governance 合约地址: `0x0d113bDe369DC8Df8e24760473bB3C4965a17078`
- 网络: MeChain 测试网 (`https://testnet-rpc.mechain.tech`)

## 🚀 快速开始

### 1. 快速创建任务
```bash
./quick-create-task.sh
```

### 2. 交互式管理
```bash
./task-manager.sh
```

## 📖 详细功能

### 任务创建

#### 1. 自动创建任务（推荐）
```bash
node create-task.js
```
- 自动生成随机种子和当前时间戳
- 调用 `createNewTaskRequest` 方法
- 自动保存返回的 attestors 信息

#### 2. 自定义参数创建任务
通过交互式脚本选择自定义参数选项，或直接修改脚本传入参数。

### 任务查看

#### 1. 查看当前任务
```bash
node view-tasks.js
```

#### 2. 查看指定任务
```bash
node view-tasks.js task <任务ID>
```

#### 3. 查看本地保存的 Attestors
```bash
node view-tasks.js local
```

#### 4. 查看任务历史
```bash
node view-tasks.js history
```

## 📁 数据存储

### 文件结构
```
task-management/
├── data/
│   ├── latest-attestors.json    # 最新的 attestors 信息
│   └── tasks-history.json       # 任务历史记录
├── create-task.js               # 创建任务脚本
├── view-tasks.js               # 查看任务脚本
├── task-manager.sh             # 交互式管理脚本
└── quick-create-task.sh        # 快速创建脚本
```

### 数据格式

#### latest-attestors.json
```json
{
  "taskId": "2",
  "timestamp": "2024-06-27T02:30:00.000Z",
  "seed": "0x1234...",
  "requestTimestamp": 1719456600,
  "attestors": [
    {
      "address": "0xaef2Ba08B0f836c81ed975452507825B5497e62f",
      "host": "wss://devint-reclaim0.mechain.tech/ws"
    }
  ]
}
```

#### tasks-history.json
```json
[
  {
    "taskId": "1",
    "timestamp": "2024-06-27T02:25:00.000Z",
    "seed": "0x5678...",
    "requestTimestamp": 1719456300,
    "attestors": [...]
  },
  {
    "taskId": "2",
    "timestamp": "2024-06-27T02:30:00.000Z",
    "seed": "0x1234...",
    "requestTimestamp": 1719456600,
    "attestors": [...]
  }
]
```

## 🔧 功能说明

### createNewTaskRequest 方法
- **参数**: 
  - `seed` (bytes32): 随机种子
  - `timestamp` (uint32): 时间戳
- **返回值**: 
  - `taskId` (uint32): 新创建的任务ID
  - `attestors` (Attestor[]): 分配给任务的 attestors 数组

### Attestor 结构
```solidity
struct Attestor {
    address addr;    // attestor 的以太坊地址
    string host;     // attestor 的连接地址
}
```

## 📊 示例输出

### 创建任务成功
```
🔗 正在连接到 MeChain 测试网...
📋 ReclaimTask 合约地址: 0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820
🌐 网络: https://testnet-rpc.mechain.tech
👤 发送地址: 0xe44973079dfA1E56F6A5de82C167F7e6fD610cc5

📊 正在获取合约基本信息...
当前任务ID: 1
所需attestors数量: 1
任务持续时间: 86400 秒 (1 天)

🎲 任务参数:
Seed: 0x1234567890abcdef...
Timestamp: 1719456600 (2024-06-27 10:30:00)

🚀 正在创建新任务...
📝 交易哈希: 0xabcd1234...
⏳ 等待交易确认...
✅ 交易已确认! Gas使用量: 150000

============================================================
🎉 任务创建成功!
============================================================
新任务ID: 2
任务开始时间: 2024-06-27 10:30:00
任务结束时间: 2024-06-28 10:30:00
分配的Attestors数量: 1

👥 分配的Attestors:
🔸 Attestor 1:
   地址: 0xaef2Ba08B0f836c81ed975452507825B5497e62f
   Host: wss://devint-reclaim0.mechain.tech/ws

💾 正在保存attestors信息到本地文件...
✅ Attestors信息已保存到:
   最新信息: data/latest-attestors.json
   历史记录: data/tasks-history.json

============================================================
✅ 任务创建完成!
============================================================
```

## 🛠️ 故障排除

### 常见问题

1. **合约调用失败**
   - 检查网络连接
   - 确认合约地址是否正确
   - 检查账户余额是否足够支付 gas 费用

2. **文件保存失败**
   - 检查目录权限
   - 确保有足够的磁盘空间

3. **依赖问题**
   ```bash
   cd .. && npm install
   ```

## 📞 下一步使用

创建任务后，您可以：

1. **使用保存的 attestors 信息**
   - 读取 `data/latest-attestors.json` 文件
   - 获取 attestors 的地址和连接信息
   - 用于下一步的 attestors 调用

2. **验证任务状态**
   - 使用 `view-tasks.js` 查看任务详情
   - 检查任务是否正确创建
   - 监控任务的执行状态

3. **集成到其他脚本**
   - 导入 `create-task.js` 模块
   - 使用 `getLatestAttestors()` 函数获取最新数据
   - 使用 `getTasksHistory()` 函数获取历史数据
