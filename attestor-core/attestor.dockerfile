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
RUN npm run download:zk-files

# 检查并备份 zk 文件
RUN echo "=== 检查 ZK 文件下载情况 ===" && \
    find node_modules/@reclaimprotocol/zk-symmetric-crypto -name "*.wasm" -o -name "*.zkey" | head -10 && \
    mkdir -p /tmp/zk-backup && \
    cp -r node_modules/@reclaimprotocol/zk-symmetric-crypto/resources /tmp/zk-backup/ && \
    echo "✅ ZK 文件已备份到 /tmp/zk-backup"

RUN npm run build:browser
RUN npm prune --production

# 创建简单的启动脚本
RUN echo '#!/bin/bash' > /app/init-zk.sh && \
    echo 'ZK_DIR="/app/node_modules/@reclaimprotocol/zk-symmetric-crypto/resources"' >> /app/init-zk.sh && \
    echo 'if [ ! -f "$ZK_DIR/snarkjs/aes-256-ctr/circuit.wasm" ]; then' >> /app/init-zk.sh && \
    echo '  echo "🔄 ZK 文件缺失，重新下载..."' >> /app/init-zk.sh && \
    echo '  cd /app && npm run download:zk-files' >> /app/init-zk.sh && \
    echo '  echo "✅ ZK 文件下载完成"' >> /app/init-zk.sh && \
    echo 'else' >> /app/init-zk.sh && \
    echo '  echo "✅ ZK 文件已存在"' >> /app/init-zk.sh && \
    echo 'fi' >> /app/init-zk.sh && \
    echo 'exec "$@"' >> /app/init-zk.sh && \
    chmod +x /app/init-zk.sh

ENTRYPOINT ["/app/init-zk.sh"]
CMD ["npm", "run", "start"]
EXPOSE 8001