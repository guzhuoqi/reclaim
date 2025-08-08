# Session-based API匹配功能

## 概述

实现了第一个功能点：基于task session记录的API匹配系统。该系统能够：

1. 维护task session记录数据库
2. 通过URL相似度算法匹配API请求到provider配置
3. 自动调用attestor node处理匹配的请求

## 核心组件

### 1. TaskSessionDB (`task_session_db.py`)

维护task session记录的数据库，支持：

- **按日期分割存储**：文件格式 `sessions_YYYY-MM-DD.json`
- **ID索引**：每个session有唯一ID
- **状态管理**：Pending、Finished、Failed
- **字段结构**：
  ```json
  {
    "id": "session_uuid",
    "taskId": "task_id_for_attestor_db",
    "providerId": "provider_id",
    "status": "Pending|Finished|Failed",
    "created_at": "2025-08-07T10:00:00Z",
    "updated_at": "2025-08-07T10:00:00Z"
  }
  ```

### 2. URLMatcher (`url_matcher.py`)

实现URL相似度匹配算法：

- **字符串相似度算法**：
  - SequenceMatcher (Ratcliff/Obershelp算法)
  - Jaccard相似度
  - Levenshtein编辑距离
- **匹配规则**：
  1. 问号前的基础URL完全匹配
  2. 综合相似度评分超过阈值（默认0.8）
- **权重配置**：基础URL权重60%，参数权重40%

### 3. ProviderQuery (`provider_query.py`)

从reclaim_providers文件中检索provider配置：

- **文件扫描**：自动扫描 `../main-flow/data/reclaim_providers_*.json`
- **格式兼容**：支持新的索引格式和旧的数组格式
- **URL提取**：从provider配置中提取所有相关URL
- **缓存机制**：文件修改时间检查，避免重复加载

### 4. SessionBasedMatcher (`session_based_matcher.py`)

核心匹配逻辑：

- **Pending Session检查**：查找状态为Pending的sessions
- **URL匹配**：使用URLMatcher进行相似度匹配
- **Attestor DB查询**：检查是否已有attestor响应
- **状态更新**：根据匹配结果更新session状态

### 5. AttestorForwardingAddon (修改版)

集成session-based匹配到mitmproxy addon：

- **请求拦截**：在原有逻辑前添加session匹配检查
- **自动调用**：匹配成功时自动调用attestor
- **响应处理**：处理attestor响应并更新session状态

## 使用方法

### 1. 创建Session记录

```python
from task_session_db import get_task_session_db

db = get_task_session_db()
session_id = db.create_session(
    task_id="attestor_task_123",
    provider_id="provider_uuid",
    additional_data={
        "url": "https://example.com/api",
        "method": "GET"
    }
)
```

### 2. 运行URL匹配测试

```python
from url_matcher import URLMatcher

matcher = URLMatcher()
result = matcher.calculate_url_similarity(url1, url2)
print(f"相似度: {result['composite_score']:.3f}")
print(f"基础URL匹配: {result['base_exact_match']}")
```

### 3. 查询Provider配置

```python
from provider_query import get_provider_query

query = get_provider_query()
provider = query.get_provider_by_id("provider_id")
urls = query.get_provider_urls("provider_id")
matches = query.find_providers_by_url_pattern("target_url")
```

### 4. 启动mitmproxy with Session匹配

```bash
cd mitmproxy2swagger/mitmproxy_addons
mitmproxy -s attestor_forwarding_addon.py --set attestor_enabled=true
```

### 5. 运行测试

```bash
cd mitmproxy2swagger/mitmproxy_addons
python3 test_session_matching.py
```

## 工作流程

1. **Session创建**：外部系统创建task session记录，状态为Pending
2. **请求拦截**：mitmproxy拦截HTTP请求
3. **Session匹配**：
   - 查找所有Pending状态的sessions
   - 通过providerId获取provider配置
   - 使用URL相似度算法匹配请求URL
4. **Attestor调用**：
   - 如果匹配成功且attestor_db中无响应，调用attestor
   - 如果已有响应，直接返回结果
5. **状态更新**：根据处理结果更新session状态

## 匹配算法详解

### URL相似度计算

1. **基础URL提取**：提取问号前的部分
2. **多算法评分**：
   - SequenceMatcher：基于最长公共子序列
   - Jaccard：基于字符集合交集/并集
   - Levenshtein：基于编辑距离
3. **综合评分**：三种算法的平均值
4. **特殊规则**：基础URL完全匹配时给予高分(0.9+)

### 匹配优先级

1. **基础URL完全匹配** (最高优先级)
2. **综合相似度 >= 0.8**
3. **综合相似度 >= 0.6** (可配置阈值)

## 配置选项

### URLMatcher配置

```python
matcher = URLMatcher()
matcher.set_similarity_threshold(0.8)  # 设置相似度阈值
matcher.set_weights(0.6, 0.4)  # 设置基础URL和参数权重
```

### 数据目录配置

```python
# TaskSessionDB
db = TaskSessionDB(base_dir="custom/path/task_sessions")

# ProviderQuery  
query = ProviderQuery(data_dir="custom/path/providers")
```

## 监控和调试

### 查看Session状态

```python
from task_session_db import get_task_session_db

db = get_task_session_db()
pending = db.get_pending_sessions()
print(f"Pending sessions: {len(pending)}")
```

### 查看匹配统计

```python
from session_based_matcher import get_session_matcher

matcher = get_session_matcher()
stats = matcher.get_matching_statistics()
print(f"统计信息: {stats}")
```

### 运行周期性检查

```python
matcher = get_session_matcher()
result = matcher.run_periodic_check()
print(f"更新了 {result['updated_sessions']} 个sessions")
```

## 文件结构

```
mitmproxy2swagger/mitmproxy_addons/
├── task_session_db.py              # Session数据库
├── url_matcher.py                  # URL匹配算法
├── provider_query.py               # Provider查询
├── session_based_matcher.py        # 核心匹配逻辑
├── attestor_forwarding_addon.py    # 修改后的mitmproxy addon
├── test_session_matching.py        # 测试脚本
├── README_session_matching.md      # 本文档
└── data/
    ├── task_sessions/              # Session数据目录
    │   ├── sessions_2025-08-07.json
    │   └── sessions_2025-08-08.json
    └── attestor_db/                # Attestor数据目录
```

## 注意事项

1. **数据目录**：确保 `../main-flow/data` 目录存在且包含provider文件
2. **权限**：确保对数据目录有读写权限
3. **依赖**：需要安装mitmproxy和相关依赖
4. **性能**：大量session时建议定期清理过期数据
5. **并发**：使用线程锁确保数据一致性

## 故障排除

### 常见问题

1. **找不到provider文件**：检查 `../main-flow/data` 目录
2. **URL匹配失败**：调整相似度阈值或检查URL格式
3. **Session状态不更新**：检查attestor_db连接
4. **权限错误**：确保数据目录可写

### 调试模式

在代码中添加更多调试输出：

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```
