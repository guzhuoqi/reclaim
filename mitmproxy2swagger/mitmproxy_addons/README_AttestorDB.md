# Attestor 数据库系统

简单的文件数据库系统，用于存储和管理 attestor 请求和响应数据。

## 🏗️ **系统架构**

```
data/attestor_db/
├── requests/           # 请求数据
│   ├── requests_2025-08-07.jsonl
│   ├── requests_2025-08-08.jsonl
│   └── ...
├── responses/          # 响应数据
│   ├── responses_2025-08-07.jsonl
│   ├── responses_2025-08-08.jsonl
│   └── ...
└── index/             # 索引文件
    ├── index_2025-08-07.jsonl
    ├── index_2025-08-08.jsonl
    └── ...
```

## 📊 **数据格式**

### 请求记录 (requests_*.jsonl)
```json
{
  "request_id": "uuid-string",
  "timestamp": 1754552025.123,
  "datetime": "2025-08-07 15:33:45 UTC",
  "date": "2025-08-07",
  "data": {
    "task_id": "task_1_1754552025",
    "url": "https://www.cmbwinglungbank.com/...",
    "method": "POST",
    "attestor_params": {...}
  },
  "status": "pending"
}
```

### 响应记录 (responses_*.jsonl)
```json
{
  "request_id": "uuid-string",
  "timestamp": 1754552039.456,
  "datetime": "2025-08-07 15:33:59 UTC",
  "date": "2025-08-07",
  "execution_time": 14.39,
  "success": true,
  "data": {
    "success": true,
    "receipt": {...},
    "extractedParameters": {"HKD": "7,151.78", "USD": "30.75"}
  }
}
```

### 索引记录 (index_*.jsonl)
```json
{
  "request_id": "uuid-string",
  "date": "2025-08-07",
  "request_timestamp": 1754552025.123,
  "response_timestamp": 1754552039.456,
  "success": true,
  "status": "completed"
}
```

## 🔧 **使用方法**

### 1. 基本查询

```bash
# 列出今天的请求
python query_attestor_db.py list

# 列出指定日期的请求
python query_attestor_db.py list --date 2025-08-07

# 获取特定请求的详细信息
python query_attestor_db.py get <request-id>

# 显示详细信息
python query_attestor_db.py get <request-id> --verbose
```

### 2. 统计信息

```bash
# 显示总体统计
python query_attestor_db.py stats

# 显示特定日期的统计
python query_attestor_db.py stats --date 2025-08-07
```

### 3. 数据导出

```bash
# 导出指定日期的数据
python query_attestor_db.py export 2025-08-07 -o backup_2025-08-07.json
```

### 4. 清理旧数据

```bash
# 清理30天前的数据
python query_attestor_db.py cleanup --days 30
```

## 🐍 **Python API**

```python
from attestor_db import get_attestor_db

# 获取数据库实例
db = get_attestor_db()

# 生成请求ID
request_id = db.generate_request_id()

# 保存请求
db.save_request(request_id, {
    "task_id": "task_1",
    "url": "https://example.com",
    "method": "POST",
    "attestor_params": {...}
})

# 保存响应
db.save_response(request_id, {
    "success": True,
    "receipt": {...},
    "extractedParameters": {...}
}, execution_time=14.39)

# 查询数据
request_data = db.get_request(request_id)
response_data = db.get_response(request_id)
complete_record = db.get_complete_record(request_id)

# 列出请求
requests = db.list_requests_by_date("2025-08-07", limit=50)

# 获取统计信息
stats = db.get_statistics()
```

## 🎯 **特性**

### ✅ **按天分割**
- 文件按日期自动分割，避免单个文件过大
- 便于备份和归档特定日期的数据

### ✅ **唯一ID关联**
- 每个请求都有唯一的 UUID
- 请求和响应通过 request_id 关联
- 支持异步查询和索引

### ✅ **高效索引**
- 独立的索引文件提供快速查找
- 支持按日期、状态、成功率等维度查询

### ✅ **并发安全**
- 使用文件锁确保并发写入安全
- 支持多进程同时访问

### ✅ **数据完整性**
- JSONL 格式确保部分损坏不影响其他记录
- 每条记录都是独立的 JSON 对象

## 📈 **性能优化**

### 文件大小控制
- 按天分割避免单文件过大
- 自动清理旧数据
- 压缩存储（可选）

### 查询优化
- 索引文件提供快速查找
- 内存缓存常用索引
- 支持日期范围查询

### 并发处理
- 文件级锁定
- 批量写入优化
- 异步处理支持

## 🔍 **监控和维护**

### 日常监控
```bash
# 查看今天的统计
python query_attestor_db.py stats

# 检查最近的请求
python query_attestor_db.py list --limit 10
```

### 定期维护
```bash
# 每周清理旧数据
python query_attestor_db.py cleanup --days 30

# 备份重要数据
python query_attestor_db.py export $(date +%Y-%m-%d) -o backup_$(date +%Y%m%d).json
```

## 🚀 **集成示例**

系统已自动集成到 mitmproxy addon 中：

1. **自动保存请求**：每个 attestor 任务创建时自动保存
2. **自动保存响应**：任务完成时自动保存结果
3. **错误记录**：所有错误和异常都会被记录
4. **实时监控**：可以实时查询任务状态和结果

这个简单的文件数据库系统提供了完整的数据持久化和查询功能，满足 attestor 系统的数据管理需求。
