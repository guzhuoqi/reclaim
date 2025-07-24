# 前端调用 Reclaim Attestor 获取 Claim 示例

本示例演示了前端如何直接使用 `@reclaimprotocol/attestor-core` SDK 调用 attestor 节点获取 claim。

## 📋 前提条件

在运行此示例之前，请确保：

1. **使用固定任务**: 本示例使用固定的任务ID `53`，无需额外创建任务
2. **网络连接**: 确保能够访问 attestor 节点的 WebSocket 地址
3. **准备用户私钥**: 用户已准备好用于签名的私钥

## 🚀 快速开始

### 1. 安装依赖

```bash
npm install
```

### 2. 配置参数

编辑 `index.js` 文件中的配置参数：

```javascript
// 用户私钥（请使用您自己的私钥）
const userPrivateKey = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

// 任务信息（使用固定的已创建任务）
const taskId = '53'; // 固定使用任务ID 53
const attestorHost = 'wss://devint-reclaim0.mechain.tech/ws'; // Attestor WebSocket地址
const attestorAddress = '0xaef2Ba08B0f836c81ed975452507825B5497e62f'; // Attestor地址
```

### 3. 运行示例

```bash
npm start
```

## 📖 代码说明

### 核心调用

```javascript
const result = await createClaimOnAttestor({
  // Provider 配置
  name: 'http',                    // 使用 HTTP provider
  params: providerParams,          // HTTP 请求参数
  secretParams: secretParams,      // 敏感参数（如 headers）
  context: context,                // 上下文信息
  
  // 用户签名配置
  ownerPrivateKey: userPrivateKey, // 用户私钥
  
  // Attestor 连接配置
  client: {
    url: attestorHost              // Attestor WebSocket 地址
  }
});
```

### 参数说明

#### Provider 参数 (`providerParams`)
- `method`: HTTP 方法 (GET/POST)
- `url`: 目标 API 地址
- `responseMatches`: 响应匹配规则，用于提取数据
- `responseRedactions`: 响应数据脱敏规则

#### 秘密参数 (`secretParams`)
- `headers`: HTTP 请求头（如 User-Agent 等）
- 其他敏感信息

#### 上下文 (`context`)
- `taskId`: 任务ID
- `timestamp`: 时间戳
- `description`: 描述信息

### 返回结果

成功时返回包含以下信息的对象：
- `claim`: 声明信息
  - `identifier`: 声明ID
  - `provider`: Provider 类型
  - `owner`: 拥有者地址
  - `timestampS`: 时间戳
  - `context`: 包含提取的数据
- `signatures`: 签名信息
  - `attestorAddress`: Attestor 地址
  - `claimSignature`: 声明签名
  - `resultSignature`: 结果签名
- `backendData`: 格式化的后端服务数据

### 后端服务集成

示例会自动打印用于后端服务的标准化数据格式：

```json
{
  "taskId": "53",
  "attestorAddress": "0xaef2ba08b0f836c81ed975452507825b5497e62f",
  "attestorHost": "wss://devint-reclaim0.mechain.tech/ws",
  "success": true,
  "response": {
    "claim": {
      "provider": "http",
      "parameters": "...",
      "owner": "0x...",
      "timestampS": 1753172814,
      "context": "...",
      "identifier": "0x...",
      "epoch": 1
    },
    "signatures": {
      "attestorAddress": "0x...",
      "claimSignature": [65个字节的数组],
      "resultSignature": [65个字节的数组]
    }
  },
  "timestamp": "2025-07-24T06:27:13.818Z"
}
```

这个数据可以直接发送给后端 API 进行：
- Claim 验证和存储
- 链上验证或提交  
- 业务逻辑处理
- 生成最终的证明或凭证

## 🔧 自定义配置

### 使用不同的 Provider

```javascript
// 示例：调用不同的 API
const providerParams = {
  method: 'GET',
  url: 'https://api.github.com/users/octocat',
  responseMatches: [{
    type: 'regex',
    value: '"login":\\s*"(?<username>[^"]+)".*"public_repos":\\s*(?<repos>\\d+)'
  }],
  responseRedactions: []
};
```

### 添加自定义 Headers

```javascript
const secretParams = {
  headers: {
    'User-Agent': 'MyApp/1.0',
    'Authorization': 'Bearer your-token', // 如果需要认证
    'Accept': 'application/json'
  }
};
```

## ⚠️ 注意事项

1. **私钥安全**: 请妥善保管私钥，不要在生产环境中硬编码私钥
2. **网络连接**: 确保能够访问 attestor 节点的 WebSocket 地址
3. **任务状态**: 确保任务已正确创建且处于可用状态
4. **错误处理**: 示例包含了基本的错误处理，生产环境中请根据需要扩展

## 🐛 常见问题

### 连接失败
- 检查 attestor 主机地址是否正确
- 确认网络连接正常
- 验证任务ID是否有效

### 签名失败
- 检查私钥格式是否正确
- 确认私钥对应的地址与任务创建时使用的地址一致

### 数据提取失败
- 检查 `responseMatches` 正则表达式是否正确
- 确认目标 API 返回的数据格式符合预期

## 📚 更多资源

- [Reclaim Protocol 文档](https://docs.reclaimprotocol.org/)
- [Attestor Core SDK 文档](https://github.com/reclaimprotocol/attestor-core)
- [Provider 配置指南](https://docs.reclaimprotocol.org/providers) 