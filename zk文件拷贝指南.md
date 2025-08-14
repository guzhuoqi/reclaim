# ZK文件拷贝指南

## 📋 概述

为了避免每次构建attestor-core和mitm镜像时重复下载ZK文件（耗时较长），我们可以预先下载ZK文件，然后在构建时直接拷贝。

## 🎯 预下载的ZK文件位置

**源文件路径**：`/Users/gu/IdeaProjects/zk-symmetric-crypto`

这个目录包含了完整的ZK电路文件，包括：
- `resources/` - ZK电路资源文件
- `bin/` - 二进制文件

## 🔧 使用方法

### 方案1：构建前预拷贝（推荐）

#### 1. 拷贝到attestor-core项目
```bash
# 进入attestor-core目录
cd /Users/gu/IdeaProjects/reclaim/attestor-core

# 创建目标目录
mkdir -p node_modules/@reclaimprotocol/zk-symmetric-crypto

# 拷贝ZK文件
cp -r /Users/gu/IdeaProjects/zk-symmetric-crypto/resources \
      node_modules/@reclaimprotocol/zk-symmetric-crypto/

cp -r /Users/gu/IdeaProjects/zk-symmetric-crypto/bin \
      node_modules/@reclaimprotocol/zk-symmetric-crypto/

echo "✅ ZK文件拷贝完成到attestor-core"
```

#### 2. 验证拷贝结果
```bash
# 检查关键文件是否存在
ls -la node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/snarkjs/*/circuit.wasm
ls -la node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/snarkjs/*/circuit.zkey

# 统计文件数量
echo "文件总数: $(find node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f | wc -l)"
```

### 方案2：Docker构建时挂载（高效）

#### 1. 修改docker-compose.yml
```yaml
services:
  attestor-core:
    build:
      context: ./attestor-core
      dockerfile: ./attestor.dockerfile
    volumes:
      # 挂载预下载的ZK文件
      - /Users/gu/IdeaProjects/zk-symmetric-crypto/resources:/app/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources:ro
      - /Users/gu/IdeaProjects/zk-symmetric-crypto/bin:/app/node_modules/@reclaimprotocol/zk-symmetric-crypto/bin:ro
```

#### 2. 修改Dockerfile跳过下载
在`attestor.dockerfile`中添加检查逻辑：
```dockerfile
# 检查是否已有ZK文件（通过挂载提供）
RUN if [ -f "/app/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/snarkjs/aes-256-ctr/circuit.wasm" ]; then \
        echo "✅ 检测到预挂载的ZK文件，跳过下载"; \
    else \
        echo "📥 未检测到ZK文件，执行下载"; \
        npm run download:zk-files; \
    fi
```

### 方案3：创建拷贝脚本

#### 1. 创建自动化脚本
```bash
#!/bin/bash
# 文件名: copy-zk-files.sh

set -e

ZK_SOURCE="/Users/gu/IdeaProjects/zk-symmetric-crypto"
ATTESTOR_TARGET="/Users/gu/IdeaProjects/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto"

echo "🚀 开始拷贝ZK文件..."

# 检查源目录
if [ ! -d "$ZK_SOURCE" ]; then
    echo "❌ 源目录不存在: $ZK_SOURCE"
    exit 1
fi

# 创建目标目录
mkdir -p "$ATTESTOR_TARGET"

# 拷贝文件
echo "📁 拷贝 resources 目录..."
cp -r "$ZK_SOURCE/resources" "$ATTESTOR_TARGET/"

echo "📁 拷贝 bin 目录..."
cp -r "$ZK_SOURCE/bin" "$ATTESTOR_TARGET/"

# 验证拷贝结果
RESOURCE_COUNT=$(find "$ATTESTOR_TARGET/resources" -type f | wc -l)
echo "📊 拷贝完成，resources目录文件数: $RESOURCE_COUNT"

# 检查关键文件
CRITICAL_FILES=(
    "resources/snarkjs/aes-256-ctr/circuit.wasm"
    "resources/snarkjs/aes-128-ctr/circuit.wasm"
    "resources/snarkjs/chacha20/circuit.wasm"
    "resources/snarkjs/aes-256-ctr/circuit.zkey"
    "resources/snarkjs/aes-128-ctr/circuit.zkey"
    "resources/snarkjs/chacha20/circuit.zkey"
)

echo "🔍 验证关键文件..."
for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$ATTESTOR_TARGET/$file" ]; then
        SIZE=$(stat -f%z "$ATTESTOR_TARGET/$file" 2>/dev/null || stat -c%s "$ATTESTOR_TARGET/$file")
        echo "  ✅ $file ($(($SIZE / 1024 / 1024)) MB)"
    else
        echo "  ❌ $file (缺失)"
    fi
done

echo "🎉 ZK文件拷贝完成！"
```

#### 2. 使用脚本
```bash
# 赋予执行权限
chmod +x copy-zk-files.sh

# 执行拷贝
./copy-zk-files.sh
```

## 📊 文件大小参考

典型的ZK文件大小：
- `circuit.wasm` 文件：约 1-5 MB 每个
- `circuit.zkey` 文件：约 50-200 MB 每个
- 总大小：约 500-800 MB

## ⚡ 性能对比

| 方法 | 构建时间 | 网络使用 | 稳定性 |
|------|----------|----------|--------|
| 重复下载 | 5-10分钟 | 高 | 依赖网络 |
| 预拷贝 | 10-30秒 | 无 | 高 |
| 挂载 | 5-10秒 | 无 | 最高 |

## 🔧 故障排除

### 问题1：拷贝后构建仍然下载
**原因**：智能下载脚本检测文件不完整
**解决**：确保拷贝了完整的`resources`和`bin`目录

### 问题2：文件权限问题
**原因**：Docker容器内用户权限不匹配
**解决**：
```bash
# 修复权限
sudo chown -R $(whoami):$(whoami) node_modules/@reclaimprotocol/zk-symmetric-crypto
```

### 问题3：文件损坏
**原因**：拷贝过程中断或源文件损坏
**解决**：重新从源仓库下载完整文件

## 📝 注意事项

1. **版本一致性**：确保拷贝的ZK文件版本与package.json中的版本匹配
2. **完整性检查**：拷贝后验证关键文件存在且大小合理
3. **定期更新**：当zk-symmetric-crypto包更新时，需要重新下载源文件
4. **备份建议**：建议将ZK文件打包备份，避免重复下载

## 🎯 最佳实践

1. **首次设置**：使用方案1预拷贝文件
2. **日常开发**：使用方案2挂载方式，最高效
3. **CI/CD**：使用方案3脚本自动化
4. **团队共享**：将ZK文件打包分享给团队成员

---

**更新时间**：2025-08-14  
**适用版本**：@reclaimprotocol/zk-symmetric-crypto@3.0.5
