# 本地 Attestor 运行步骤

## 1. 准备配置文件

使用 `boc-hk-enhanced.json` 配置文件（已配置好命名捕获组的正则表达式）：

```json
"responseMatches": [
  {
    "type": "regex",
    "value": "data_table_swap1_txt data_table_lastcell\"[^>]*>(?<hkd_balance>[\\d,]+\\.\\d{2})</td>"
  },
  {
    "type": "regex",
    "value": "data_table_swap2_txt data_table_lastcell\"[^>]*>(?<usd_balance>[\\d,]+\\.\\d{2})</td>"
  },
  {
    "type": "regex",
    "value": "data_table_subtotal data_table_lastcell\"[^>]*>(?<total_balance>[\\d,]+\\.\\d{2})</td>"
  }
]
```

## 2. 运行本地 Attestor

```bash
PRIVATE_KEY=0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89 npm run create:claim -- --json boc-hk-enhanced.json --attestor local
```

## 3. 验证结果

检查输出中的关键信息：
- ✅ `generated ZK proofs`
- ✅ `receipt is valid for http provider`
- ✅ `extractedParameters` 包含余额数据
- ✅ 文件生成：`boc-claim-object-{timestamp}.json`

## 4. 检查生成的文件

```bash
ls -la boc-claim-object-*.json
grep "extractedParameters" boc-claim-object-*.json
```

余额数据应包含：
- `hkd_balance`: 港元余额
- `usd_balance`: 美元余额  
- `total_balance`: 总计余额