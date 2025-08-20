ARG NODE_IMAGE=node:20-bookworm
FROM ${NODE_IMAGE}

# Install Python and pip for mitmproxy and addon deps
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv ca-certificates curl make g++ && \
    rm -rf /var/lib/apt/lists/*

# Copy OpenSSL configuration files to fix legacy renegotiation issue
COPY ./mitmproxy2swagger/docker-configs/openssl-legacy.cnf /etc/ssl/openssl-legacy.cnf
COPY ./mitmproxy2swagger/docker-configs/fix-openssl.sh /usr/local/bin/fix-openssl.sh

# Fix OpenSSL legacy renegotiation issue for container proxy traffic
RUN chmod +x /usr/local/bin/fix-openssl.sh && \
    /usr/local/bin/fix-openssl.sh

# Set environment variables for OpenSSL
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf \
    SSL_CERT_DIR=/etc/ssl/certs

WORKDIR /opt/reclaim

# Build-time toggles for attestor-core handling
ARG SKIP_ATTESTOR_BUILD=false
ARG USE_PREBUILT_LIB=true
# Install devDependencies during build so TypeScript and build-time tools are available
# We'll prune devDeps after build to keep the final image slim
ARG NPM_CI_ARGS=

# Copy and (optionally) build attestor-core (for local script execution inside addon)
COPY ./attestor-core/package.json ./attestor-core/package-lock.json /opt/reclaim/attestor-core/
RUN mkdir -p /opt/reclaim/attestor-core/src/scripts \
    && sh -lc 'echo "" > /opt/reclaim/attestor-core/src/scripts/prepare.sh' \
    && if [ "$SKIP_ATTESTOR_BUILD" != "true" ]; then \
         cd /opt/reclaim/attestor-core && npm ci --include=optional $NPM_CI_ARGS ; \
       else \
         echo "⏭️  Skip npm ci for attestor-core (will rely on runtime volume)" ; \
       fi
COPY ./attestor-core /opt/reclaim/attestor-core
RUN if [ "$SKIP_ATTESTOR_BUILD" != "true" ]; then \
      cd /opt/reclaim/attestor-core && \
      if [ "$USE_PREBUILT_LIB" = "true" ] && [ -d lib ] ; then \
        echo "⚡ Using prebuilt attestor-core lib (skip build)" ; \
      else \
        echo "🔧 Building attestor-core from source" && npm run build ; \
      fi && \
      echo "🔍 检查ZK文件状态..." && \
      if [ -f "node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/snarkjs/aes-256-ctr/circuit.wasm" ]; then \
        echo "✅ 检测到预拷贝的ZK文件，跳过下载" && \
        echo "📊 现有ZK文件数量: $(find node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f 2>/dev/null | wc -l)"; \
      else \
        echo "📥 未检测到ZK文件，执行下载..." && \
        npm run download:zk-files && \
        echo "📊 ZK文件下载完成，文件数量: $(find node_modules/@reclaimprotocol/zk-symmetric-crypto/resources -type f 2>/dev/null | wc -l)"; \
      fi && \
      npm prune --omit=dev ; \
    else \
      echo "⏭️  Skip attestor-core build (will rely on runtime volume)" ; \
    fi

# Create compatibility symlink for code paths expecting /opt/attestor-core
RUN ln -s /opt/reclaim/attestor-core /opt/attestor-core

# Copy addon code after base is ready, preserve repo structure
COPY ./mitmproxy2swagger /opt/reclaim/mitmproxy2swagger
WORKDIR /opt/reclaim/mitmproxy2swagger/mitmproxy_addons

# Python deps for mitmweb runtime
# Use isolated venv to avoid PEP 668 restriction
RUN python3 -m venv /venv
ENV PATH="/venv/bin:${PATH}"
RUN pip3 --version && python3 --version && pip3 install --no-cache-dir \
    "mitmproxy==9.0.1" \
    websocket-client \
    requests \
    "httpx[http2,brotli]" \
    psutil

# Create data/logs directories inside container
RUN mkdir -p /app/mitmproxy_addons/logs /app/mitmproxy_addons/data

EXPOSE 8080 8082 8083

# Default command: run mitmweb and sidecar flows proxy to avoid 403 from cross-container clients
CMD ["sh", "-lc", "(/venv/bin/python flows_proxy.py & echo $! > /tmp/flows_proxy.pid) && /venv/bin/mitmweb -s attestor_forwarding_addon.py --listen-host 0.0.0.0 --listen-port 8080 --set web_host=0.0.0.0 --set web_port=8082 --set web_open_browser=false --set block_global=false --set block_private=false --set web_iface=0.0.0.0 --set confdir=/tmp --no-web-open-browser | tee -a logs/mitmweb.log"]


