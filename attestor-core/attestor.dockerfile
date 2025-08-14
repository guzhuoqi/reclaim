ARG NODE_IMAGE=node:20-bookworm
FROM ${NODE_IMAGE}

# install build tools for native modules (re2) and git
RUN apt update -y && apt upgrade -y && apt install -y git python3 make g++ && rm -rf /var/lib/apt/lists/*

ARG GL_TOKEN
RUN git config --global url."https://git-push-pull:${GL_TOKEN}@gitlab.reclaimprotocol.org".insteadOf "https://gitlab.reclaimprotocol.org"

COPY ./package.json /app/
COPY ./package-lock.json /app/
RUN mkdir -p /app/src/scripts
RUN echo '' > /app/src/scripts/prepare.sh

WORKDIR /app

RUN npm ci --include=optional

COPY ./ /app

RUN npm run build

# 🚀 使用智能ZK文件下载器：避免不必要的删除和重新下载
RUN npm run download:zk-files

# 检查 ZK 文件下载情况
RUN echo "=== 检查 ZK 文件下载情况 ===" && \
    find node_modules/@reclaimprotocol/zk-symmetric-crypto -name "*.wasm" -o -name "*.zkey" | head -10 && \
    echo "ZK 文件总数: $(find node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f | wc -l)"

RUN npm run build:browser

# 创建目标目录并 COPY ZKP 文件到指定位置
RUN mkdir -p /opt/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources && \
    echo "📁 创建目标目录: /opt/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources"

# COPY 构建时生成的 ZKP 文件到目标目录
RUN if [ -d "node_modules/@reclaimprotocol/zk-symmetric-crypto/resources" ]; then \
        cp -r node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/* \
              /opt/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/ && \
        echo "✅ ZKP 文件已 COPY 到: /opt/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources" && \
        echo "📊 COPY 后文件数量: $(find /opt/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f | wc -l)"; \
    else \
        echo "❌ 源 ZK 文件目录不存在"; \
        exit 1; \
    fi

# 验证关键文件是否存在
RUN echo "🔍 验证关键 ZKP 文件..." && \
    for algo in aes-256-ctr aes-128-ctr chacha20; do \
        wasm_file="/opt/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/snarkjs/$algo/circuit.wasm"; \
        if [ -f "$wasm_file" ]; then \
            echo "✅ $algo/circuit.wasm 存在 ($(stat -c%s "$wasm_file") bytes)"; \
        else \
            echo "❌ $algo/circuit.wasm 缺失"; \
        fi; \
    done

RUN npm prune --production

# 创建启动脚本，确保运行时 ZKP 文件可用
RUN echo '#!/bin/bash' > /app/init-zk.sh && \
    echo 'echo "🔄 检查 ZKP 文件可用性..."' >> /app/init-zk.sh && \
    echo 'ZK_DIR="/app/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources"' >> /app/init-zk.sh && \
    echo 'ZK_SOURCE="/opt/reclaim/attestor-core/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources"' >> /app/init-zk.sh && \
    echo 'if [ ! -f "$ZK_DIR/snarkjs/aes-256-ctr/circuit.wasm" ]; then' >> /app/init-zk.sh && \
    echo '  echo "📁 运行时 ZK 目录为空，从构建时备份恢复..."' >> /app/init-zk.sh && \
    echo '  mkdir -p "$ZK_DIR"' >> /app/init-zk.sh && \
    echo '  if [ -d "$ZK_SOURCE" ]; then' >> /app/init-zk.sh && \
    echo '    cp -r "$ZK_SOURCE"/* "$ZK_DIR"/' >> /app/init-zk.sh && \
    echo '    echo "✅ ZKP 文件从构建时备份恢复完成"' >> /app/init-zk.sh && \
    echo '  else' >> /app/init-zk.sh && \
    echo '    echo "⚠️ 构建时备份不存在，重新下载..."' >> /app/init-zk.sh && \
    echo '    cd /app && npm run download:zk-files' >> /app/init-zk.sh && \
    echo '  fi' >> /app/init-zk.sh && \
    echo 'else' >> /app/init-zk.sh && \
    echo '  echo "✅ ZKP 文件已存在，跳过恢复"' >> /app/init-zk.sh && \
    echo 'fi' >> /app/init-zk.sh && \
    echo 'echo "🚀 启动应用..."' >> /app/init-zk.sh && \
    echo 'exec "$@"' >> /app/init-zk.sh && \
    chmod +x /app/init-zk.sh

ENTRYPOINT ["/app/init-zk.sh"]
CMD ["npm", "run", "start"]
EXPOSE 8001