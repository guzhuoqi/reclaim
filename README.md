# MeChain Reclaim Protocol Tools

## 📋 项目概述

这是一个完整的 MeChain Reclaim 协议工具集，包含了 attestor 节点交互、合约管理、proof 生成和验证的完整工作流程。

## 🏗️ 项目结构

```
reclaim/
├── attestor-contracts/          # 合约交互工具
│   ├── node-query/             # 查询已注册的 attestor 节点
│   ├── task-management/        # 创建和管理 ReclaimTask 合约
│   ├── attestor-calls/         # 直接 RPC 调用 attestor 节点生成 ZKP
│   ├── proof-verification/     # 链上验证 proofs 并保存完整审计记录
│   └── scripts/               # 原有 Hardhat 脚本
│
├── attestor-core/              # Attestor 节点核心代码
│   ├── src/                   # 源代码
│   ├── proto/                 # Protocol Buffers 定义
│   ├── example/               # 使用示例
│   └── docs/                  # 文档
│
└── README.md                  # 本文档
```

## 🚀 快速开始

### 完整工作流程

1. **查看已注册节点**
   ```bash
   cd attestor-contracts/node-query
   ./quick-view-nodes.sh
   ```

2. **创建新任务**
   ```bash
   cd attestor-contracts/task-management
   ./quick-create-task.sh
   ```

3. **调用 Attestors 生成 Proofs**
   ```bash
   cd attestor-contracts/attestor-calls
   ./quick-call-attestors.sh
   ```

4. **验证 Proofs**
   ```bash
   cd attestor-contracts/proof-verification
   ./quick-verify-proofs.sh
   ```

## 📚 详细文档

### attestor-contracts/
完整的合约交互工具集，包含四个主要功能模块：

- **[节点查询](attestor-contracts/node-query/node-query-guide.md)** - 查看已注册的 attestor 节点
- **[任务管理](attestor-contracts/task-management/README.md)** - 创建和管理 ReclaimTask 合约
- **[Attestor 调用](attestor-contracts/attestor-calls/README.md)** - 直接 RPC 调用 attestor 节点生成 ZKP
- **[Proof 验证](attestor-contracts/proof-verification/README.md)** - 链上验证 proofs 并保存完整审计记录

### attestor-core/
Attestor 节点的核心实现代码，包含：

- **RPC API 定义** - Protocol Buffers 接口定义
- **客户端库** - 用于与 attestor 节点通信的客户端
- **示例代码** - 如何使用 attestor-core 的示例
- **文档** - API 文档和使用说明

## 🔧 环境配置

### 前置要求
- Node.js >= 16
- npm 或 yarn
- Git

### 安装依赖

**attestor-contracts:**
```bash
cd attestor-contracts
npm install
```

**attestor-core:**
```bash
cd attestor-core
npm install
```

### 环境变量配置

在 `attestor-contracts/` 目录下创建 `.env` 文件：
```env
PRIVATE_KEY=your_private_key_here
NETWORK_URL=https://testnet-rpc.mechain.tech
RECLAIM_TASK_ADDRESS=0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820
GOVERNANCE_ADDRESS=0x0d113bDe369DC8Df8e24760473bB3C4965a17078
```

## 🎯 主要功能特性

### ✅ 完整的工作流程
- 从节点查询到最终验证的完整流程
- 每个步骤都有详细的数据记录和审计追踪

### ✅ 中文界面支持
- 所有交互式脚本都提供中文界面
- 清晰的操作提示和错误信息

### ✅ 数据分离存储
- 验证入参、RPC 请求、链上结果分别存储
- 便于审计和数据分析

### ✅ 直接 RPC 调用
- 绕过中间服务，直接与 attestor 节点通信
- 使用 attestor-core 库进行 ZKP 生成

### ✅ 完整的错误处理
- 详细的错误信息和恢复建议
- 自动重试和状态检查

## 📊 使用示例

### 典型使用场景：验证 Binance ETH 价格

1. **创建任务获取 attestors**
2. **调用 attestors 获取 ETH 价格数据并生成 ZKP**
3. **在链上验证 proofs 并达成共识**

整个流程会生成完整的审计记录，包括：
- 任务创建记录
- Attestor 调用记录和返回的 proofs
- 链上验证的交易哈希和结果

## 🔗 相关链接

- **MeChain 测试网**: https://testnet-rpc.mechain.tech
- **合约地址**: 
  - ReclaimTask: `0x2ce4693Ea2a41941F0A798A62BC1eE9c3c31c820`
  - Governance: `0x0d113bDe369DC8Df8e24760473bB3C4965a17078`

## 📝 开发说明

### 贡献指南
1. Fork 本仓库
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request

### 代码结构
- `attestor-contracts/` - 合约交互工具，使用 JavaScript/Node.js
- `attestor-core/` - Attestor 节点核心，使用 TypeScript

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🤝 支持

如有问题或建议，请创建 Issue 或联系维护者。

# 招商永隆银行 Provider

基于验证过的mitmproxy抓包分析和数据提取技术构建的zkTLS Provider

## 🎯 验证成果

- **验证银行**: 招商永隆银行 (CMB Wing Lung Bank)
- **验证数据**: HKD 7,150.98, USD 30.75, CNY 0.00
- **核心API**: NbBkgActdetCoaProc2022
- **数据准确性**: 100% (与用户浏览器显示完全一致)

## 🏗️ 技术架构

### 核心组件

```
CMBWingLungProvider          # 基础Provider类
├── authenticate()           # 用户认证
├── get_balance()           # 获取单账户余额  
├── get_full_account_info() # 获取完整账户信息
└── validate_balance_data() # 数据验证

ReclaimCMBWingLungProvider  # Reclaim协议集成
└── create_balance_claim()  # 创建余额证明claim

BankBalanceExtractor        # 数据提取器 (来自验证过的分析工具)
└── extract_data()          # 正则表达式数据提取
```

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 基础使用

```python
from cmb_wing_lung_provider import ReclaimCMBWingLungProvider

# 创建Provider实例
provider = ReclaimCMBWingLungProvider()

# 用户认证和余额查询
credentials = {
    "username": "your_username",
    "password": "your_password"
}

# 创建余额证明claim
claim = provider.create_balance_claim(credentials)

if claim['success']:
    print("✅ 余额证明创建成功")
    print(f"🏦 银行: {claim['data']['bank']}")
    print(f"💰 总余额: {claim['data']['total_balances']}")
else:
    print(f"❌ 失败: {claim['error']}")
```

## 📊 支持的账户类型

| 代码 | 账户类型 | 说明 |
|------|----------|------|
| CON  | 活期账户 | 主要往来账户 ✅ 已验证 |
| DDA  | 往来账户 | 支票账户 |
| SAV  | 储蓄账户 | 储蓄存款 |
| FDA  | 定期账户 | 定期存款 |
| CUR  | 外币账户 | 外币存款 |
| MEC  | 综合账户 | 综合理财 |

## 💰 支持的货币

- **HKD** (港币) ✅ 已验证: 7,150.98
- **USD** (美元) ✅ 已验证: 30.75  
- **CNY** (人民币) ✅ 已验证: 0.00

## 🧪 测试

```bash
# 运行基础测试
python3 cmb_wing_lung_provider.py

# 运行完整测试
python3 test_provider.py
```

## ⚠️ 重要说明

1. **实际数据**: Provider基于100%真实的抓包数据构建，无任何模拟数据
2. **安全性**: 请妥善保管用户凭据
3. **合规性**: 请确保使用符合当地法律法规和银行服务条款

---

**基于验证过的技术 • 100%真实数据 • 生产级可用**
