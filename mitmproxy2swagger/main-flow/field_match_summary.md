# 抓包文件字段匹配分析报告

## 📊 总体统计

- **分析文件数**: 7 个 mitm 文件
- **总流量数**: 3,131 个 HTTP 请求
- **分析响应数**: 2,437 个响应
- **分析时间**: 2025-01-09 05:56:57

## 🎯 字段匹配结果

| 字段 | 匹配次数 | 匹配率 | 模式 |
|------|----------|--------|------|
| **phone** | 95 | 3.9% | `"phone"` |
| **email** | 85 | 3.5% | `"email"` |
| **currency** | 65 | 2.7% | `"currency"` |

## 📋 详细分析

### 1. Phone 字段 (95 次匹配)

**主要出现场景**:
- 银行网站的 JavaScript 代码中
- Google Analytics/Tag Manager 脚本中
- 表单验证和转换跟踪代码

**典型上下文**:
```javascript
// 表单验证相关
showDivNum($(this), "phone");

// Google Analytics 转换跟踪
"phone_conversion_callback"
"phone_conversion_country_code" 
"phone_conversion_number"
```

### 2. Email 字段 (85 次匹配)

**主要出现场景**:
- Google Analytics/Tag Manager 脚本
- LinkedIn Analytics 脚本
- 用户数据处理和转换跟踪

**典型上下文**:
```javascript
// 数据类型判断
case Mx.Mb:return"email";

// 表单字段处理
b===\"email\"||b===\"phone_number\"?5:1

// 类型设置
case Mx.Mb:b.set("type","email")
```

### 3. Currency 字段 (65 次匹配)

**主要出现场景**:
- Google Analytics/Tag Manager 脚本
- 电商和支付相关的跟踪代码
- 货币和交易处理

**典型上下文**:
```javascript
// Google Analytics 参数映射
Ya:"currency"

// 货币代码处理
t==="currencyCode"?n("currency",q.currencyCode)
```

## 🏦 主要来源网站

根据分析结果，这些字段主要出现在以下类型的网站：

1. **银行网站**:
   - 中国建设银行 (ccb.com)
   - 中银香港 (bochk.com)
   - 表单验证和用户输入处理

2. **第三方分析服务**:
   - Google Tag Manager
   - Google Analytics
   - LinkedIn Analytics
   - 用户行为跟踪和转换分析

3. **JavaScript 框架和库**:
   - 表单验证库
   - 数据处理工具
   - UI 组件库

## 💡 关键发现

### 1. 匹配模式分布
- **Phone**: 最高匹配率 (3.9%)，主要用于表单验证和转换跟踪
- **Email**: 中等匹配率 (3.5%)，广泛用于用户身份识别
- **Currency**: 较低匹配率 (2.7%)，主要用于电商和支付场景

### 2. 技术特征
- 大部分匹配来自 **JavaScript 代码**，而非 API 响应数据
- 主要是 **配置参数** 和 **字段名定义**，而非实际数据值
- 集中在 **前端分析工具** 和 **表单处理** 代码中

### 3. 数据质量评估
- 这些匹配主要是 **字段名称** 而非实际的敏感数据
- 大部分来自 **公开的 JavaScript 库** 和分析工具
- 对于 Reclaim Protocol 的数据提取价值 **相对较低**

## 🔍 建议

### 1. 优化匹配策略
- 考虑更精确的匹配模式，区分字段名和实际数据
- 增加上下文分析，识别真正的数据字段
- 过滤掉分析工具和框架代码的匹配

### 2. 关注真实数据
- 重点关注 API 响应中的结构化数据
- 寻找 JSON 格式的用户数据和交易信息
- 识别银行业务相关的实际数据字段

### 3. 改进检测规则
```json
{
  "type": "regex",
  "value": "\"(phone|email|currency)\"\\s*:\\s*\"[^\"]+\"",
  "description": "匹配实际的键值对数据"
}
```

## 📁 相关文件

- 详细分析结果: `data/field_match_analysis_20250809_055657.json`
- 分析脚本: `analyze_field_matches.py`
- 原始抓包文件: `temp/*.mitm`
