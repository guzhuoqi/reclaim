# mitmproxy定制化转发Addon

一个功能强大的mitmproxy扩展，专为银行API抓包和智能转发设计。

## 🌟 核心功能

### 1. 智能URL过滤
- **静态资源过滤**: 自动过滤CSS、JS、图片等静态文件
- **低价值API过滤**: 过滤健康检查、统计等非关键API
- **高优先级API识别**: 自动识别银行余额、交易等关键API

### 2. 定制化转发
- **银行API专用转发**: 支持中国银行香港、招商永隆等银行
- **域名智能匹配**: 支持通配符域名匹配
- **Header管理**: 自动保留认证信息，添加代理标识

### 3. 安全控制
- **域名白名单/黑名单**: 精确控制允许访问的域名
- **速率限制**: 防止API滥用和过载
- **请求验证**: 多层安全检查机制

### 4. 实时监控
- **详细日志记录**: 记录所有转发决策和操作
- **性能指标收集**: 统计处理量、转发成功率等
- **可视化监控**: 通过管理工具查看实时状态

## 🚀 快速开始

### 1. 安装依赖

```bash
# 安装mitmproxy
pip install mitmproxy

# 确保项目依赖已安装
cd mitmproxy2swagger
pip install -r requirements.txt  # 如果有的话
```

### 2. 启动服务

```bash
# 启动Web界面版本 (推荐)
python3 start_mitmproxy_with_addon.py --mode web

# 启动命令行版本
python3 start_mitmproxy_with_addon.py --mode proxy

# 启动并保存流量到文件
python3 start_mitmproxy_with_addon.py --mode dump --output flows.mitm
```

### 3. 配置浏览器代理

```bash
# Chrome浏览器代理设置
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-certificate-errors \
  --user-data-dir=/tmp/chrome_dev_session
```

### 4. 访问Web界面

打开浏览器访问: `http://127.0.0.1:8082`

## 📋 配置管理

### 查看当前配置

```bash
python3 mitmproxy_addons/forwarding_manager.py --config
```

### 测试URL匹配

```bash
# 测试银行API URL
python3 mitmproxy_addons/forwarding_manager.py --test-url "https://bochk.com/api/balance"

# 测试静态资源URL
python3 mitmproxy_addons/forwarding_manager.py --test-url "https://example.com/static/style.css"
```

### 添加转发规则

```bash
python3 mitmproxy_addons/forwarding_manager.py \
  --add-rule "新银行" \
  --source-domains "newbank.com" "*.newbank.com" \
  --target-host "api-proxy.newbank.internal" \
  --target-port 443
```

### 监控运行状态

```bash
python3 mitmproxy_addons/forwarding_manager.py --monitor
```

## 🔧 配置文件说明

配置文件位置: `mitmproxy_addons/forwarding_config.json`

### 主要配置项

```json
{
  "global_settings": {
    "enable_logging": true,
    "log_level": "INFO",
    "enable_metrics": true
  },
  
  "url_filtering": {
    "static_resources": {
      "enabled": true,
      "action": "block",
      "patterns": ["\\.(css|js|jpg|png|gif)$"]
    }
  },
  
  "forwarding_rules": {
    "bank_apis": {
      "enabled": true,
      "rules": [
        {
          "name": "中国银行香港",
          "source_domains": ["bochk.com", "*.bochk.com"],
          "target_host": "api-proxy.bochk.internal",
          "target_port": 443
        }
      ]
    }
  },
  
  "security": {
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 100
    },
    "allowed_domains": ["bochk.com", "cmbwinglungbank.com"]
  }
}
```

## 📊 监控和日志

### 日志文件

- **转发日志**: `logs/forwarding_addon.log`
- **性能指标**: `logs/forwarding_metrics.json`

### 关键指标

- `total_requests`: 总请求数
- `total_responses`: 总响应数
- `forwarded_requests`: 转发请求数
- `filtered_static_resources`: 过滤的静态资源数
- `blocked_requests`: 被阻止的请求数
- `rate_limited_requests`: 被速率限制的请求数

## 🎯 银行API专用功能

### 支持的银行

1. **中国银行香港** (bochk.com)
2. **招商永隆银行** (cmbwinglungbank.com)

### 自动识别的API类型

- 余额查询API: `*/balance*`
- 账户信息API: `*/account*`
- 交易记录API: `*/transaction*`
- 支付转账API: `*/payment*`, `*/transfer*`
- 认证相关API: `*/login*`, `*/auth*`

### Header处理

**自动保留的Headers:**
- `Authorization`: 认证令牌
- `Cookie`: 会话信息
- `X-CSRF-Token`: CSRF保护令牌

**自动添加的Headers:**
- `X-Proxy-Source`: 标识代理来源
- `X-Bank-Code`: 银行代码标识

## 🔍 故障排除

### 常见问题

1. **mitmproxy未找到**
   ```bash
   pip install mitmproxy
   # 或者
   brew install mitmproxy  # macOS
   ```

2. **配置文件格式错误**
   ```bash
   python3 mitmproxy_addons/forwarding_manager.py --config
   ```

3. **证书问题**
   - 访问 `http://mitm.it` 下载并安装证书
   - 在浏览器中信任mitmproxy证书

4. **端口冲突**
   ```bash
   python3 start_mitmproxy_with_addon.py --mode web --web-port 8083 --listen-port 8081
   ```

### 调试模式

```bash
# 启用详细日志
python3 start_mitmproxy_with_addon.py --mode web
# 然后修改配置文件中的 log_level 为 "DEBUG"
```

## 📚 高级用法

### 自定义过滤规则

编辑 `forwarding_config.json` 中的 `url_filtering` 部分:

```json
{
  "url_filtering": {
    "custom_filter": {
      "enabled": true,
      "action": "block",
      "patterns": [
        "/admin/.*",
        "/internal/.*"
      ]
    }
  }
}
```

### 动态配置更新

配置文件支持热重载，修改后无需重启服务。

### 集成现有系统

可以将此Addon集成到现有的mitmproxy工作流中:

```bash
mitmproxy -s mitmproxy_addons/custom_forwarding_addon.py --set forwarding_enabled=true
```

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 📄 许可证

本项目采用MIT许可证。
