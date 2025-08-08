# 解决银行网站SSL错误指南

## 问题描述

访问工商银行等银行网站时出现以下错误：
```
502 Bad Gateway
OpenSSL Error([('SSL routines', '', 'unsafe legacy renegotiation disabled')])
```

## 问题原因

这个错误是因为：
1. **OpenSSL默认禁用了不安全的传统SSL重新协商功能**
2. **部分银行网站仍在使用旧的SSL/TLS协商方式**
3. **mitmproxy在处理这些网站时无法完成SSL握手**

## 解决方案

### 方案1：使用增强版mitmweb启动脚本（推荐）

已为你创建了 `start_mitmweb_with_legacy_ssl.sh` 脚本，它包含以下特性：

- ✅ **启用传统SSL重新协商支持**
- ✅ **降低TLS安全等级**  
- ✅ **支持TLSv1.0等旧版协议**
- ✅ **自动清理临时配置文件**

#### 使用步骤：

1. **启动增强版mitmproxy**：
   ```bash
   ./start_mitmweb_with_legacy_ssl.sh
   ```

2. **启动Chrome浏览器**：
   ```bash
   ./start_chrome_with_proxy.sh
   ```

3. **访问银行网站**：
   - 工商银行：https://mybank.icbc.com.cn/
   - 中国银行：https://ebsnew.boc.cn/

### 方案2：手动配置环境变量

如果你想手动启动mitmproxy，可以设置以下环境变量：

```bash
# 设置环境变量
export OPENSSL_ALLOW_UNSAFE_LEGACY_RENEGOTIATION=1

# 创建OpenSSL配置文件
cat > /tmp/openssl_legacy.conf << 'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Options = UnsafeLegacyRenegotiation
CipherString = DEFAULT@SECLEVEL=1
EOF

# 设置配置文件路径
export OPENSSL_CONF=/tmp/openssl_legacy.conf

# 启动mitmweb
mitmweb --set listen_port=9999 --set web_port=8082 \
        --set ssl_insecure=true \
        --set tls_version_client_min=TLSV1 \
        --set tls_version_server_min=TLSV1
```

## 配置文件说明

### OpenSSL配置关键参数

- `UnsafeLegacyRenegotiation`：启用不安全的传统SSL重新协商
- `DEFAULT@SECLEVEL=1`：降低安全等级，支持旧的加密算法
- `legacy = legacy_sect`：启用传统算法提供程序

### mitmproxy配置关键参数

- `--set ssl_insecure=true`：允许不安全的SSL连接
- `--set tls_version_client_min=TLSV1`：支持TLSv1.0及以上版本
- `--set tls_version_server_min=TLSV1`：服务器端也支持TLSv1.0

## 测试验证

启动服务后，可以测试以下银行网站：

| 银行 | 网址 | 预期结果 |
|------|------|----------|
| 工商银行 | https://mybank.icbc.com.cn/ | ✅ 正常访问 |
| 中国银行 | https://ebsnew.boc.cn/ | ✅ 正常访问 |
| 建设银行 | https://ibsbjstar.ccb.com.cn/ | ✅ 正常访问 |
| 招商银行 | https://pbsz.ebank.cmbchina.com/ | ✅ 正常访问 |

## 安全提醒

⚠️ **重要提醒**：

1. **仅用于开发测试**：这些配置降低了SSL安全性，仅应用于开发和测试环境
2. **不要用于生产环境**：生产环境应使用安全的SSL配置
3. **临时配置**：脚本会在退出时自动清理临时配置文件

## 常见问题

### Q1：仍然出现SSL错误怎么办？

**A1**：检查以下几点：
- 确认环境变量已正确设置
- 重启mitmproxy和Chrome浏览器
- 尝试清除Chrome的SSL状态：`chrome://settings/privacy`

### Q2：Chrome显示"您的连接不是私密连接"？

**A2**：这是正常现象，点击"高级" → "继续前往xxx（不安全）"即可。

### Q3：某些银行网站仍无法访问？

**A3**：部分银行可能使用了更严格的安全策略，可以尝试：
- 添加更多Chrome启动参数
- 使用不同的TLS版本配置
- 检查是否有其他网络拦截

## 文件说明

- `start_mitmweb_with_legacy_ssl.sh`：增强版mitmproxy启动脚本
- `start_chrome_with_proxy.sh`：Chrome代理启动脚本
- `/tmp/openssl_legacy.conf`：临时OpenSSL配置文件（自动清理）

---

📝 **最后更新**：2025-01-25  
🔧 **适用版本**：mitmproxy 10.x+, OpenSSL 3.x+