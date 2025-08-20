#!/bin/bash
# 构建 attestor-core 镜像（预拷贝ZK文件版本）

set -e

echo "🚀 开始构建 attestor-core 镜像（预拷贝ZK文件）"
echo "=" * 60

# 配置路径
ZK_SOURCE="/Users/gu/IdeaProjects/zk-symmetric-crypto"
ATTESTOR_DIR="/Users/gu/IdeaProjects/reclaim/attestor-core"
ZK_TARGET="$ATTESTOR_DIR/node_modules/@reclaimprotocol/zk-symmetric-crypto"

# 检查源ZK文件目录
if [ ! -d "$ZK_SOURCE" ]; then
    echo "❌ ZK源文件目录不存在: $ZK_SOURCE"
    echo "💡 请确保已下载完整的 zk-symmetric-crypto 项目"
    exit 1
fi

echo "📁 ZK源文件目录: $ZK_SOURCE"
echo "📁 Attestor目录: $ATTESTOR_DIR"

# 进入 attestor-core 目录
cd "$ATTESTOR_DIR"

# 创建目标目录
echo "📁 创建ZK目标目录..."
mkdir -p "$ZK_TARGET"

# 拷贝ZK文件
echo "📥 拷贝ZK文件..."
echo "  拷贝 resources 目录..."
cp -r "$ZK_SOURCE/resources" "$ZK_TARGET/"

echo "  拷贝 bin 目录..."
cp -r "$ZK_SOURCE/bin" "$ZK_TARGET/"

# 验证拷贝结果
echo "🔍 验证拷贝结果..."
RESOURCE_COUNT=$(find "$ZK_TARGET/resources" -type f 2>/dev/null | wc -l)
echo "📊 resources目录文件数: $RESOURCE_COUNT"

# 检查关键文件
CRITICAL_FILES=(
    "resources/snarkjs/aes-256-ctr/circuit.wasm"
    "resources/snarkjs/aes-128-ctr/circuit.wasm"
    "resources/snarkjs/chacha20/circuit.wasm"
    "resources/snarkjs/aes-256-ctr/circuit_final.zkey"
    "resources/snarkjs/aes-128-ctr/circuit_final.zkey"
    "resources/snarkjs/chacha20/circuit_final.zkey"
)

echo "🔍 验证关键文件..."
for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$ZK_TARGET/$file" ]; then
        SIZE=$(stat -f%z "$ZK_TARGET/$file" 2>/dev/null || stat -c%s "$ZK_TARGET/$file")
        echo "  ✅ $file ($(($SIZE / 1024 / 1024)) MB)"
    else
        echo "  ❌ $file (缺失)"
        echo "❌ 关键文件缺失，构建可能失败"
        exit 1
    fi
done

echo "✅ ZK文件拷贝完成！"
echo ""

# 构建Docker镜像
echo "🐳 开始构建Docker镜像..."
echo "=" * 40

# 设置构建参数
DOCKER_TAG="attestor-core:latest"
GL_TOKEN="${GL_TOKEN:-dummy_token}"

echo "🏷️  镜像标签: $DOCKER_TAG"
echo "🔑 GL_TOKEN: ${GL_TOKEN:0:10}..."

# 执行Docker构建
docker build \
    --build-arg GL_TOKEN="$GL_TOKEN" \
    --tag "$DOCKER_TAG" \
    --file attestor.dockerfile \
    .

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 attestor-core 镜像构建成功！"
    echo "🏷️  镜像标签: $DOCKER_TAG"
    echo ""
    echo "📋 使用方法:"
    echo "  docker run -p 8001:8001 $DOCKER_TAG"
    echo ""
    echo "🔍 验证镜像:"
    echo "  docker images | grep attestor-core"
    echo ""
else
    echo "❌ Docker镜像构建失败"
    exit 1
fi

echo "✅ 构建流程完成！"
