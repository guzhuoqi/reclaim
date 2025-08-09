# HTTP到Attestor转换器

将mitmproxy抓包得到的HTTP请求转换为attestor node调用参数的工具。

## 🎯 功能特性

- ✅ **智能Headers分离**：自动区分基础headers和敏感headers
- ✅ **Cookie提取**：自动提取Cookie到secretParams.cookieStr
- ✅ **响应匹配模式**：支持预定义和自定义的正则表达式模式
- ✅ **命令行生成**：直接生成可执行的create:claim命令
- ✅ **多种输入方式**：支持mitmproxy Flow对象和原始请求数据

## 📦 文件结构

```
mitmproxy_addons/
├── http_to_attestor_converter.py  # 核心转换器
├── test_converter.py              # 测试脚本
├── example_usage.py               # 使用示例
└── README_converter.md            # 本文档
```

## 🚀 快速开始

### 1. 基本使用

```python
from http_to_attestor_converter import HttpToAttestorConverter

converter = HttpToAttestorConverter()

# 转换HTTP请求为attestor参数
attestor_params = converter.convert_raw_request_to_attestor_params(
    url="https://api.example.com/balance",
    method="GET",
    headers={
        "Authorization": "Bearer token123",
        "User-Agent": "Mozilla/5.0..."
    },
    custom_patterns={
        "balance": r"余额[^\\d]*(\\d[\\d,]*\\.\\d{2})"
    }
)

# 生成可执行命令
command = converter.generate_command_line(attestor_params)
print(command)
```

### 2. 银行余额查询示例

```python
# 招商永隆银行余额查询
bank_patterns = {
    "hkd_balance": r"HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})",
    "usd_balance": r"USD[^\\d]*(\\d[\\d,]*\\.\\d{2})"
}

attestor_params = converter.convert_raw_request_to_attestor_params(
    url="https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?...",
    method="POST",
    headers={
        "Host": "www.cmbwinglungbank.com",
        "Cookie": "JSESSIONID=...; dse_sessionId=...",
        "X-Requested-With": "XMLHttpRequest"
    },
    geo_location="HK",
    custom_patterns=bank_patterns
)
```

### 3. API价格查询示例

```python
# Binance ETH价格查询
price_patterns = {
    "eth_price": r'"price":"(\\d+\\.\\d+)"',
    "symbol": r'"symbol":"(\\w+)"'
}

attestor_params = converter.convert_raw_request_to_attestor_params(
    url="https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT",
    method="GET",
    headers={"Accept": "application/json"},
    geo_location="US",
    custom_patterns=price_patterns
)
```

## 🔧 API参考

### HttpToAttestorConverter类

#### 主要方法

##### `convert_raw_request_to_attestor_params()`
将原始HTTP请求数据转换为attestor参数格式。

**参数：**
- `url` (str): 请求URL
- `method` (str): HTTP方法，默认"GET"
- `headers` (Dict[str, str]): 请求headers
- `body` (str): 请求体，默认""
- `geo_location` (str): 地理位置，默认"HK"
- `response_patterns` (List[str]): 预定义模式名称列表
- `custom_patterns` (Dict[str, str]): 自定义模式字典

**返回：**
```python
{
    "name": "http",
    "params": {
        "url": "...",
        "method": "GET",
        "geoLocation": "HK",
        "body": "",
        "headers": {...},
        "responseMatches": [...],
        "responseRedactions": [...]
    },
    "secretParams": {
        "cookieStr": "...",
        "headers": {...}
    }
}
```

##### `convert_flow_to_attestor_params()`
将mitmproxy的HTTPFlow对象转换为attestor参数格式。

##### `generate_command_line()`
生成完整的create:claim命令行字符串。

##### `add_response_pattern()`
添加新的响应匹配模式。

##### `get_available_patterns()`
获取所有可用的预定义模式。

### 预定义响应模式

| 模式名称 | 描述 | 正则表达式 |
|---------|------|-----------|
| `bank_balance_hkd` | 港币余额匹配 | `HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})` |
| `bank_balance_usd` | 美元余额匹配 | `USD[^\\d]*(\\d[\\d,]*\\.\\d{2})` |
| `bank_balance_cny` | 人民币余额匹配 | `CNY[^\\d]*(\\d[\\d,]*\\.\\d{2})` |
| `account_number` | 账户号码匹配 | `账户[^\\d]*(\\d{10,20})` |
| `transaction_amount` | 交易金额匹配 | `金额[^\\d]*(\\d[\\d,]*\\.\\d{2})` |

### Headers分类规则

#### 敏感Headers（放入secretParams.headers）
- `cookie`, `authorization`, `x-auth-token`, `x-api-key`
- `sec-ch-ua*`, `user-agent`, `accept*`
- `origin`, `referer`, `sec-fetch-*`, `x-requested-with`

#### 基础Headers（保留在params.headers）
- `host`, `connection`, `content-type`, `content-length`

## 🧪 测试

运行测试脚本：
```bash
python3 test_converter.py
```

运行使用示例：
```bash
python3 example_usage.py
```

## 📝 输出格式

### 转换结果结构
```json
{
  "name": "http",
  "params": {
    "url": "https://example.com/api",
    "method": "GET",
    "geoLocation": "HK",
    "body": "",
    "headers": {
      "Host": "example.com",
      "Connection": "close",
      "User-Agent": "Mozilla/5.0...",
      "Authorization": "Bearer token"
    },
    "responseMatches": [
      {
        "type": "regex",
        "value": "pattern1"
      }
    ],
    "responseRedactions": [
      {
        "regex": "pattern1"
      }
    ]
  }
}
```

### 生成的命令格式
```bash
PRIVATE_KEY=0x0123... npm run create:claim -- \
  --name "http" \
  --params '{"url":"...","method":"GET",...}' \
  --attestor local
```

## 🔗 与Attestor Core集成

1. **确保attestor-core环境已配置**
2. **切换到attestor-core目录**
3. **执行生成的命令**
4. **等待ZK proof生成完成**
5. **获取生成的claim对象**

## 💡 使用建议

1. **响应模式设计**：根据目标API的响应格式设计合适的正则表达式
2. **地理位置设置**：根据API服务器位置设置合适的geoLocation
3. **私钥管理**：生产环境中使用真实的私钥，注意安全
4. **错误处理**：在实际集成中添加适当的错误处理和重试机制

## 🚨 注意事项

- 正则表达式中的反斜杠需要双重转义（`\\d` 而不是 `\d`）
- Cookie会自动提取到secretParams.cookieStr字段
- 敏感headers会自动分离到secretParams.headers中
- 生成的命令需要在attestor-core目录下执行

## 🔄 下一步计划

1. 集成到mitmproxy addon中实现实时转换
2. 添加异步执行支持
3. 实现进程池管理优化性能
4. 添加更多预定义的响应模式
5. 支持更复杂的数据提取规则
