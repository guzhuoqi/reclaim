# Provider索引使用说明

## 概述

新的Provider索引系统将 `reclaim_providers_YYYYMMDD.json` 文件设计成可索引的数据库结构，支持通过 `providerId` 进行高效查询，同时保持按日期拆分的特性。

## 文件结构

### 新的索引结构

```json
{
  "metadata": {
    "generated_at": "2025-08-05T11:16:05.240129",
    "date": "20250805",
    "total_providers": 1,
    "source_mitm_file": "temp/flows_export_20250805.mitm",
    "source_analysis_file": "data/feature_analysis_20250805.json",
    "generator_version": "1.0.0",
    "index_structure": "providerId_based",
    "description": "Daily provider configurations indexed by providerId for efficient lookup"
  },
  "provider_index": {
    "2e7995f2-b155-45fb-8748-6bc73cde1d7e": {
      "institution": "中银香港",
      "api_type": "balance_inquiry",
      "priority_level": "critical",
      "value_score": 120,
      "confidence_score": 1.0,
      "created_at": "2025-08-05T11:16:05.240084",
      "config_id": "a1eba6ab363047bcb009daf0"
    }
  },
  "providers": {
    "2e7995f2-b155-45fb-8748-6bc73cde1d7e": {
      "providerConfig": {
        // 完整的provider配置
      }
    }
  },
  "query_helpers": {
    "get_provider_by_id": "providers[providerId]",
    "get_provider_metadata": "provider_index[providerId]",
    "list_all_provider_ids": "Object.keys(providers)",
    "filter_by_institution": "Object.entries(provider_index).filter(([id, meta]) => meta.institution === institutionName)",
    "filter_by_api_type": "Object.entries(provider_index).filter(([id, meta]) => meta.api_type === apiType)",
    "filter_by_priority": "Object.entries(provider_index).filter(([id, meta]) => meta.priority_level === priority)"
  }
}
```

### 主要改进

1. **provider_index**: 提供快速查找的元数据索引
2. **providers**: 以 providerId 为 key 的完整配置字典
3. **query_helpers**: 提供查询方法的说明
4. **按日期拆分**: 文件名仍然包含日期，便于管理

## 使用方法

### 1. Python API

#### 加载指定日期的providers

```python
from provider_builder import ReclaimProviderBuilder

# 加载今天的providers
providers_data = ReclaimProviderBuilder.load_providers_by_date("20250805")

# 检查是否加载成功
if providers_data:
    print(f"加载了 {providers_data['metadata']['total_providers']} 个providers")
```

#### 通过providerId查询

```python
# 查询特定provider
provider_config = ReclaimProviderBuilder.query_provider_by_id(
    "2e7995f2-b155-45fb-8748-6bc73cde1d7e", 
    "20250805"
)

if provider_config:
    print("找到provider配置")
```

#### 通过机构名查询

```python
# 查询中银香港的所有providers
bank_providers = ReclaimProviderBuilder.query_providers_by_institution(
    "中银香港", 
    "20250805"
)

for provider_info in bank_providers:
    print(f"Provider ID: {provider_info['provider_id']}")
    print(f"API类型: {provider_info['metadata']['api_type']}")
```

#### 列出所有provider IDs

```python
# 获取所有provider IDs
provider_ids = ReclaimProviderBuilder.list_all_provider_ids("20250805")
print(f"共有 {len(provider_ids)} 个providers")
```

### 2. 命令行工具

#### 查看可用日期

```bash
python query_providers.py dates
```

#### 列出所有providers

```bash
# 列出今天的providers
python query_providers.py list

# 列出指定日期的providers
python query_providers.py --date 20250805 list

# 显示详细信息
python query_providers.py --verbose list
```

#### 通过ID查询provider

```bash
# 查询特定provider
python query_providers.py get 2e7995f2-b155-45fb-8748-6bc73cde1d7e

# 保存到文件
python query_providers.py get 2e7995f2-b155-45fb-8748-6bc73cde1d7e --output provider.json
```

#### 通过机构查询

```bash
# 查询中银香港的providers
python query_providers.py institution "中银香港"

# 查询指定日期的机构providers
python query_providers.py --date 20250805 institution "中银香港"
```

### 3. JavaScript/前端使用

```javascript
// 假设已加载providers_data
const providersData = /* 加载的JSON数据 */;

// 通过ID获取provider
const providerId = "2e7995f2-b155-45fb-8748-6bc73cde1d7e";
const provider = providersData.providers[providerId];

// 获取provider元数据
const metadata = providersData.provider_index[providerId];

// 列出所有provider IDs
const allIds = Object.keys(providersData.providers);

// 按机构筛选
const bankProviders = Object.entries(providersData.provider_index)
  .filter(([id, meta]) => meta.institution === "中银香港")
  .map(([id, meta]) => ({
    id,
    metadata: meta,
    config: providersData.providers[id]
  }));

// 按API类型筛选
const balanceApis = Object.entries(providersData.provider_index)
  .filter(([id, meta]) => meta.api_type === "balance_inquiry");
```

## 测试工具

### 运行索引功能测试

```bash
python test_provider_indexing.py
```

这个测试脚本会验证：
- 文件加载功能
- 索引一致性
- 查询功能
- 数据结构完整性

## 优势

1. **高效查询**: O(1) 时间复杂度通过 providerId 查找
2. **灵活筛选**: 支持按机构、API类型、优先级等条件筛选
3. **向后兼容**: 保持原有的日期分割特性
4. **易于维护**: 清晰的索引结构，便于调试和维护
5. **多语言支持**: 结构简单，易于在不同编程语言中使用

## 文件管理

- 文件按日期命名：`reclaim_providers_YYYYMMDD.json`
- 每日覆盖写入，避免重复数据
- 支持历史数据查询
- 便于备份和归档

## 注意事项

1. 确保 providerId 的唯一性
2. provider_index 和 providers 的 key 必须保持一致
3. 日期格式固定为 YYYYMMDD
4. 文件编码使用 UTF-8
