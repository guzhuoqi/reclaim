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

RUN npm ci --include=optional && \
    echo "🔽  预下载 ZK 文件以启用缓存层" && \
    npm run download:zk-files-force && \
    echo "✅  ZK 文件已缓存: $(find node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f 2>/dev/null | wc -l)"

# 不再从宿主 node_modules 拷贝，避免覆盖容器内缓存的 ZK 文件

# 🎯 优化拷贝：只拷贝源代码，避免覆盖 node_modules 中的预拷贝文件
COPY ./src /app/src
COPY ./tsconfig*.json /app/
COPY ./webpack.config.js /app/
COPY ./jest.config.js /app/
COPY ./commitlint.config.cjs /app/
COPY ./scripts /app/scripts
COPY ./proto /app/proto
COPY ./avs /app/avs
COPY ./docs /app/docs
COPY ./browser /app/browser
COPY ./cert /app/cert
COPY ./*.json /app/
COPY ./*.md /app/

RUN npm run build

# 🚀 智能ZK文件检查和下载
RUN echo "🔍 检查ZK文件状态..." && \
    if [ -f "node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/snarkjs/aes-256-ctr/circuit.wasm" ]; then \
      echo "✅ 检测到预拷贝的ZK文件，跳过下载" && \
      echo "📊 现有ZK文件数量: $(find node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f 2>/dev/null | wc -l)"; \
    else \
      echo "📥 未检测到ZK文件，执行下载..." && \
      npm run download:zk-files && \
      echo "📊 ZK文件下载完成，文件数量: $(find node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f 2>/dev/null | wc -l)"; \
    fi

RUN npm prune --production




CMD ["npm", "run", "start"]
EXPOSE 8001